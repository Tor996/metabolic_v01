package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// User struct to hold user data
type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // Store hashed password
}

// In-memory store for users (replace with a database in production)
var (
	users = make(map[string]User)
	mutex = &sync.Mutex{}
)

// Create a new cookie store for session management
var (
	// Key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	// In production, you should use environment variables or a secure key management system
	store = sessions.NewCookieStore([]byte("super-secret-key-replace-in-production"))
)

// Template caching (basic)
var templates *template.Template

func init() {
	// Configure session store
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,      // JavaScript cannot access the cookie
		// Secure:   true,   // For HTTPS only (enable in production)
		// SameSite: http.SameSiteStrictMode,
	}

	// Parse templates on startup
	templates = template.Must(template.ParseGlob("templates/*.html"))
}

// Check if user is authenticated
func isAuthenticated(r *http.Request) (string, bool) {
	session, _ := store.Get(r, "auth-session")
	username, ok := session.Values["username"].(string)
	return username, ok && username != ""
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
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		// Return HTML snippet for HTMX
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Username and password are required</div>")
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

	mutex.Lock()
	defer mutex.Unlock()

	if _, exists := users[username]; exists {
		// Return HTML snippet for HTMX
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Username already taken</div>")
		return
	}

	users[username] = User{Username: username, Password: string(hashedPassword)}

	// Create a session after registration
	session, _ := store.Get(r, "auth-session")
	session.Values["username"] = username
	session.Save(r, w)

	// Return HTML snippet for HTMX with redirect
	w.Header().Set("HX-Redirect", "/dashboard")
	fmt.Fprint(w, "<div id=\"message\" class=\"success\">User registered successfully. Redirecting...</div>")
	log.Printf("User registered: %s", username)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
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
	username := r.FormValue("username")
	password := r.FormValue("password")

	mutex.Lock()
	user, exists := users[username]
	mutex.Unlock() // Unlock early

	if !exists {
		// Return HTML snippet for HTMX
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Invalid username or password</div>")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil { // Passwords don't match
		// Return HTML snippet for HTMX
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "<div id=\"message\" class=\"error\">Invalid username or password</div>")
		return
	}

	// Login successful - create a session
	session, _ := store.Get(r, "auth-session")
	session.Values["username"] = username
	session.Save(r, w)

	// Return HTML snippet for HTMX with redirect
	w.Header().Set("HX-Redirect", "/dashboard")
	fmt.Fprint(w, "<div id=\"message\" class=\"success\">Login successful! Redirecting...</div>")
	log.Printf("User logged in: %s", username)
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

// Middleware to ensure user is authenticated
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, authenticated := isAuthenticated(r)
		if !authenticated {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		log.Printf("Authenticated user accessing: %s - %s", username, r.URL.Path)
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
	username, authenticated := isAuthenticated(r)
	if authenticated {
		// User is already logged in, redirect to dashboard
		log.Printf("Already authenticated user: %s", username)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Dashboard handler for authenticated users
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	username, _ := isAuthenticated(r)
	data := map[string]interface{}{"Username": username}

	err := templates.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		log.Printf("Error executing dashboard template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func main() {
	// Static file server
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Auth routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	// Protected routes
	http.HandleFunc("/dashboard", requireAuth(dashboardHandler))

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
