package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"example.com/myproject/db/sqlite" // Import our SQLite package

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// Database connection
var database *sqlite.DB

// Create a new cookie store for session management
var store *sessions.CookieStore

// Template caching (basic)
var templates *template.Template

// CSRF token store with mutex for concurrent access
var csrfTokens = struct {
	sync.RWMutex
	tokens map[string]time.Time
}{tokens: make(map[string]time.Time)}

// Define middleware type
type Middleware func(http.Handler) http.Handler

// MiddlewareChain represents a chain of middleware
type MiddlewareChain struct {
	middlewares []Middleware
}

// NewMiddlewareChain creates a new middleware chain
func NewMiddlewareChain(middlewares ...Middleware) MiddlewareChain {
	return MiddlewareChain{middlewares: middlewares}
}

// Then applies the middleware chain to an http.Handler
func (c MiddlewareChain) Then(handler http.Handler) http.Handler {
	// Apply middlewares in reverse order
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		handler = c.middlewares[i](handler)
	}
	return handler
}

// ThenFunc applies the middleware chain to an http.HandlerFunc
func (c MiddlewareChain) ThenFunc(handlerFunc http.HandlerFunc) http.Handler {
	return c.Then(http.HandlerFunc(handlerFunc))
}

// Common middleware functions

// LoggingMiddleware logs information about each request
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)
		
		next.ServeHTTP(w, r)
		
		log.Printf("Completed %s %s in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// TimeoutMiddleware adds a timeout to the request context
func TimeoutMiddleware(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware ensures the user is authenticated
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, authenticated := isAuthenticated(r)
		if !authenticated {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		
		// Add the user email to the request context for use in handlers
		ctx := context.WithValue(r.Context(), "userEmail", email)
		r = r.WithContext(ctx)
		
		log.Printf("Authenticated user accessing: %s - %s", email, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// MethodCheckMiddleware ensures the request uses the correct HTTP method
func MethodCheckMiddleware(method string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRFProtectionMiddleware adds CSRF protection to forms
func CSRFProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("CSRF middleware processing: %s %s", r.Method, r.URL.Path)
		
		// Skip CSRF check for GET, HEAD, OPTIONS, TRACE
		if r.Method == http.MethodGet || r.Method == http.MethodHead || 
		   r.Method == http.MethodOptions || r.Method == http.MethodTrace {
			// For GET requests, set a CSRF token in the session
			if r.Method == http.MethodGet {
				session, _ := store.Get(r, "auth-session")
				
				// Generate token if it doesn't exist
				if session.Values["csrf_token"] == nil {
					token := generateCSRFToken()
					session.Values["csrf_token"] = token
					session.Save(r, w)
					
					// Store token with expiration
					csrfTokens.Lock()
					csrfTokens.tokens[token] = time.Now().Add(24 * time.Hour)
					csrfTokens.Unlock()
					
					log.Printf("Generated new CSRF token for session")
				} else {
					// Make sure existing token is in the token map
					token := session.Values["csrf_token"].(string)
					
					csrfTokens.RLock()
					_, exists := csrfTokens.tokens[token]
					csrfTokens.RUnlock()
					
					if !exists {
						// Re-add token to storage if it's missing
						csrfTokens.Lock()
						csrfTokens.tokens[token] = time.Now().Add(24 * time.Hour)
						csrfTokens.Unlock()
						log.Printf("Re-added existing session token to storage")
					} else {
						log.Printf("Using existing CSRF token from session")
					}
				}
				
				// Add the token to request context
				ctx := context.WithValue(r.Context(), "csrf_token", session.Values["csrf_token"].(string))
				r = r.WithContext(ctx)
			}
			
			next.ServeHTTP(w, r)
			return
		}
		
		// For state-changing methods (POST, PUT, DELETE), verify token
		session, err := store.Get(r, "auth-session")
		if err != nil {
			log.Printf("Error getting session: %v", err)
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}
		
		sessionToken, hasToken := session.Values["csrf_token"].(string)
		log.Printf("Session has CSRF token: %v", hasToken)
		
		// Get token from form or header
		var requestToken string
		if r.Header.Get("X-CSRF-Token") != "" {
			requestToken = r.Header.Get("X-CSRF-Token")
			log.Printf("CSRF token from header: %s", requestToken)
		} else {
			err := r.ParseForm()
			if err != nil {
				log.Printf("Error parsing form: %v", err)
				http.Error(w, "Invalid form data", http.StatusBadRequest)
				return
			}
			
			requestToken = r.FormValue("csrf_token")
			log.Printf("CSRF token from form: %s", requestToken)
			log.Printf("All form values: %v", r.Form)
		}
		
		// Validate token
		if !hasToken || sessionToken == "" || requestToken == "" || sessionToken != requestToken {
			log.Printf("CSRF token validation failed: path=%s, sessionToken=%s, requestToken=%s", 
				r.URL.Path, sessionToken, requestToken)
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
			return
		}
		
		// Check if token is expired
		csrfTokens.RLock()
		expiry, exists := csrfTokens.tokens[sessionToken]
		csrfTokens.RUnlock()
		
		// If token exists in session but not in storage, add it to storage with new expiry
		if !exists {
			log.Printf("Token found in session but not in storage, adding it now")
			csrfTokens.Lock()
			csrfTokens.tokens[sessionToken] = time.Now().Add(24 * time.Hour)
			exists = true
			expiry = csrfTokens.tokens[sessionToken]
			csrfTokens.Unlock()
		}
		
		if !exists || time.Now().After(expiry) {
			log.Printf("CSRF token expired or not found in storage")
			http.Error(w, "CSRF token expired", http.StatusForbidden)
			return
		}
		
		// Token is valid, proceed
		log.Printf("CSRF validation successful, proceeding with request")
		next.ServeHTTP(w, r)
	})
}

// generateCSRFToken creates a secure random token
func generateCSRFToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Clean up expired CSRF tokens periodically
func cleanupCSRFTokens() {
	for {
		time.Sleep(1 * time.Hour)
		
		csrfTokens.Lock()
		for token, expiry := range csrfTokens.tokens {
			if time.Now().After(expiry) {
				delete(csrfTokens.tokens, token)
			}
		}
		csrfTokens.Unlock()
		
		log.Printf("Cleaned up expired CSRF tokens, %d remain", len(csrfTokens.tokens))
	}
}

func init() {
	// Get session key from environment variable or use a default for development
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		// Only for development - in production, this should come from environment
		sessionKey = "super-secret-key-replace-in-production"
		log.Println("WARNING: Using default session key. Set SESSION_KEY environment variable in production.")
	}

	// Initialize the cookie store with the session key
	store = sessions.NewCookieStore([]byte(sessionKey))
	
	// Configure session store
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,      // JavaScript cannot access the cookie
		// Secure:   true,   // For HTTPS only (enable in production)
		// SameSite: http.SameSiteStrictMode,
	}

	// Create template functions map
	funcMap := template.FuncMap{
		"csrfField": func(token string) template.HTML {
			return template.HTML(`<input type="hidden" name="csrf_token" value="` + token + `">`)
		},
	}

	// Parse templates with the function map
	templates = template.New("").Funcs(funcMap)
	templates = template.Must(templates.ParseGlob("templates/*.html"))
}

// Check if user is authenticated
func isAuthenticated(r *http.Request) (string, bool) {
	session, _ := store.Get(r, "auth-session")
	email, ok := session.Values["email"].(string)
	return email, ok && email != ""
}

// ProfileData holds data for the profile template
type ProfileData struct {
	User        *sqlite.User
	Message     string
	MessageType string
	CSRFToken   string
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data instead of JSON
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if email == "" || password == "" {
		// Return HTML snippet for HTMX
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Email and password are required</div>")
		return
	}

	// Check if passwords match
	if password != confirmPassword {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Passwords do not match</div>")
		return
	}

	// Check if user already exists in the database
	existingUser, err := database.GetUserByEmail(email)
	if err != nil {
		log.Printf("Database error checking user existence: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Internal server error</div>")
		return
	}

	if existingUser != nil {
		// User already exists
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Email already registered</div>")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		// Return HTML snippet for HTMX
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Internal server error</div>")
		return
	}

	// Create user in the database - use email as username
	err = database.CreateUser(email, string(hashedPassword))
	if err != nil {
		log.Printf("Error creating user in database: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Failed to create user</div>")
		return
	}

	// Create a session after registration
	session, _ := store.Get(r, "auth-session")
	session.Values["email"] = email
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session after registration: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Session error</div>")
		return
	}

	log.Printf("User registered: %s", email)

	// Check if this is an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		// HTMX redirect
		w.Header().Set("HX-Redirect", "/dashboard")
		fmt.Fprint(w, "<div id=\"message\" class=\"success\">User registered successfully. Redirecting...</div>")
	} else {
		// Regular browser redirect (fallback)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

// Handler for the registration page
func registerPageHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is already authenticated
	_, authenticated := isAuthenticated(r)
	if authenticated {
		// User is already logged in, redirect to dashboard
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Get CSRF token from context
	csrfToken, _ := r.Context().Value("csrf_token").(string)
	
	data := map[string]interface{}{"CSRFToken": csrfToken}
	err := templates.ExecuteTemplate(w, "register.html", data)
	if err != nil {
		log.Printf("Error executing register template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Login attempt from %s", r.RemoteAddr)

	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data instead of JSON
	err := r.ParseForm()
	if err != nil {
		log.Printf("Error parsing form: %v", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	
	// Log all form data
	log.Printf("Login form data: %v", r.Form)
	
	email := r.FormValue("email")
	password := r.FormValue("password")
	
	log.Printf("Login attempt for email: %s", email)

	// Get user from database
	user, err := database.GetUserByEmail(email)
	if err != nil {
		log.Printf("Database error during login: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Internal server error</div>")
		return
	}

	if user == nil {
		// User not found
		log.Printf("User not found: %s", email)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Invalid email or password</div>")
		return
	}

	// Compare password with stored hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil { // Passwords don't match
		// Return HTML snippet for HTMX
		log.Printf("Password verification failed for %s: %v", email, err)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Invalid email or password</div>")
		return
	}

	// Login successful - create a session
	session, _ := store.Get(r, "auth-session")
	session.Values["email"] = email
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Session error</div>")
		return
	}

	log.Printf("Login successful for %s, redirecting to dashboard", email)
	
	// Check if this is an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		// HTMX redirect
		w.Header().Set("HX-Redirect", "/dashboard")
		fmt.Fprint(w, "<div id=\"message\" class=\"success\">Login successful! Redirecting...</div>")
	} else {
		// Regular browser redirect (fallback)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get and delete the session
	session, _ := store.Get(r, "auth-session")
	session.Values = map[interface{}]interface{}{}
	session.Options.MaxAge = -1 // Delete the cookie
	session.Save(r, w)

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Profile handler for viewing and editing user profile
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Get email from the session (now provided by the AuthMiddleware)
	email := r.Context().Value("userEmail").(string)
	// Get CSRF token from context
	csrfToken, _ := r.Context().Value("csrf_token").(string)

	// Get user from database
	user, err := database.GetUserByEmail(email)
	if err != nil {
		log.Printf("Database error loading profile: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		// This should not happen but handle it gracefully
		log.Printf("Authenticated user not found in database: %s", email)
		http.Redirect(w, r, "/logout", http.StatusSeeOther)
		return
	}

	// Handle GET - Display profile
	if r.Method == http.MethodGet {
		data := ProfileData{
			User: user,
			CSRFToken: csrfToken,
		}
		
		err = templates.ExecuteTemplate(w, "profile.html", data)
		if err != nil {
			log.Printf("Error executing profile template: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Handle PUT - Update profile
	if r.Method == http.MethodPut {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "<div id=\"message\" class=\"error\">Invalid form data</div>")
			return
		}

		// Get form values
		newEmail := r.FormValue("email")
		currentPassword := r.FormValue("current_password")

		// Verify current password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<div id=\"message\" class=\"error\">Current password is incorrect</div>")
			return
		}

		// Check if new email is different from current
		if newEmail != email {
			// Check if new email is already taken
			existingUser, err := database.GetUserByEmail(newEmail)
			if err != nil {
				log.Printf("Database error checking email existence: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "<div id=\"message\" class=\"error\">Internal server error</div>")
				return
			}

			if existingUser != nil {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, "<div id=\"message\" class=\"error\">Email address already in use</div>")
				return
			}

			// Update session with new email
			session, _ := store.Get(r, "auth-session")
			session.Values["email"] = newEmail
			session.Save(r, w)
		}

		// Update user details
		updates := map[string]interface{}{
			"email": newEmail,
		}

		err = database.UpdateUser(user.ID, updates)
		if err != nil {
			log.Printf("Error updating user profile: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "<div id=\"message\" class=\"error\">Failed to update profile</div>")
			return
		}

		// Return success message
		fmt.Fprint(w, "<div id=\"message\" class=\"success\">Profile updated successfully</div>")
		return
	}

	// Method not allowed
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Change password handler
func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Get email from the session (now provided by the AuthMiddleware)
	email := r.Context().Value("userEmail").(string)

	// Get user from database
	user, err := database.GetUserByEmail(email)
	if err != nil {
		log.Printf("Database error loading user for password change: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Internal server error</div>")
		return
	}

	// Parse form data
	err = r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Invalid form data</div>")
		return
	}

	// Get form values
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Check if the new password matches the confirmation
	if newPassword != confirmPassword {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">New passwords do not match</div>")
		return
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Current password is incorrect</div>")
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing new password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Failed to process new password</div>")
		return
	}

	// Update user password
	updates := map[string]interface{}{
		"password": string(hashedPassword),
	}

	err = database.UpdateUser(user.ID, updates)
	if err != nil {
		log.Printf("Error updating user password: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Failed to update password</div>")
		return
	}

	// Return success message
	fmt.Fprint(w, "<div id=\"message\" class=\"success\">Password changed successfully</div>")
}

// Middleware to ensure user is authenticated (legacy version, kept for reference)
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, authenticated := isAuthenticated(r)
		if !authenticated {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		log.Printf("Authenticated user accessing: %s - %s", email, r.URL.Path)
		next.ServeHTTP(w, r)
	}
}

// Modify the root handler to serve the HTML template
func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Prevent handling other paths like /favicon.ico
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user is already authenticated
	email, authenticated := isAuthenticated(r)
	if authenticated {
		// User is already logged in, redirect to dashboard
		log.Printf("Already authenticated user: %s", email)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Get CSRF token from context
	csrfToken, ok := r.Context().Value("csrf_token").(string)
	log.Printf("Index handler - CSRF token present: %v, token: %s", ok, csrfToken)
	
	data := map[string]interface{}{"CSRFToken": csrfToken}
	log.Printf("Template data for index: %+v", data)
	
	err := templates.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Dashboard handler for authenticated users
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value("userEmail").(string)
	csrfToken, _ := r.Context().Value("csrf_token").(string)
	
	data := map[string]interface{}{
		"Email": email,
		"CSRFToken": csrfToken,
	}

	err := templates.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		log.Printf("Error executing dashboard template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func main() {
	// Initialize database connection
	db, err := sqlite.New("")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	database = db

	// Run database migrations
	if err := db.RunMigrations(); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}
	log.Println("Database initialized successfully")

	// Start CSRF token cleanup in background
	go cleanupCSRFTokens()

	// Create a new HTTP server
	mux := http.NewServeMux()

	// Define middleware chains
	publicChain := NewMiddlewareChain(
		LoggingMiddleware,
		TimeoutMiddleware(30*time.Second),
		CSRFProtectionMiddleware,
	)
	
	privateChain := NewMiddlewareChain(
		LoggingMiddleware,
		TimeoutMiddleware(30*time.Second),
		AuthMiddleware,
		CSRFProtectionMiddleware,
	)
	
	postChain := NewMiddlewareChain(
		LoggingMiddleware,
		TimeoutMiddleware(30*time.Second),
		CSRFProtectionMiddleware,
		MethodCheckMiddleware(http.MethodPost),
	)
	
	privatePostChain := NewMiddlewareChain(
		LoggingMiddleware,
		TimeoutMiddleware(30*time.Second),
		AuthMiddleware,
		CSRFProtectionMiddleware,
		MethodCheckMiddleware(http.MethodPost),
	)
	
	// Add test route for debugging
	mux.Handle("/debug-csrf", publicChain.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth-session")
		csrfToken, ok := session.Values["csrf_token"].(string)
		
		// Print all cookies
		cookies := r.Cookies()
		cookieInfo := make([]string, len(cookies))
		for i, cookie := range cookies {
			cookieInfo[i] = fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
		}
		
		htmlOutput := fmt.Sprintf(`
			<html>
				<head><title>CSRF Debug</title></head>
				<body>
					<h1>CSRF Debug Info</h1>
					<p><strong>Session has CSRF token:</strong> %v</p>
					<p><strong>Session CSRF token:</strong> %s</p>
					<p><strong>Context CSRF token:</strong> %s</p>
					<p><strong>Cookies:</strong> %s</p>
					<h2>Test Post Form</h2>
					<form method="post" action="/debug-csrf">
						%s
						<input type="text" name="test" value="test">
						<button type="submit">Submit</button>
					</form>
				</body>
			</html>
		`, ok, csrfToken, r.Context().Value("csrf_token"), strings.Join(cookieInfo, "<br>"), 
		   template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, r.Context().Value("csrf_token"))))
		
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlOutput))
	}))
	
	// Static file server
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Public routes with appropriate middleware
	mux.Handle("/", publicChain.ThenFunc(indexHandler))
	mux.Handle("/register-page", publicChain.ThenFunc(registerPageHandler))
	mux.Handle("/register", postChain.ThenFunc(registerHandler))
	mux.Handle("/login", postChain.ThenFunc(loginHandler)) // Re-enabling CSRF protection
	mux.Handle("/logout", publicChain.ThenFunc(logoutHandler))

	// Protected routes with auth middleware
	mux.Handle("/dashboard", privateChain.ThenFunc(dashboardHandler))
	mux.Handle("/profile", privateChain.ThenFunc(profileHandler)) // Handles both GET and PUT in the handler
	mux.Handle("/change-password", privatePostChain.ThenFunc(changePasswordHandler))

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Configure the server
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Start the server in a goroutine
	go func() {
		log.Printf("Starting server on :%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %v", err)
		}
	}()

	// Set up channel to listen for interrupt or terminate signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received
	<-stop
	log.Println("Shutting down server...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server gracefully stopped")
}
