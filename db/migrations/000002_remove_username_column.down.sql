-- Create a temporary table with the username column
CREATE TABLE users_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Copy data from the current table to the new one, using email as username
INSERT INTO users_new (id, email, username, password, created_at, updated_at)
SELECT id, email, email, password, created_at, updated_at FROM users;

-- Drop the current table
DROP TABLE users;

-- Rename the new table to the original name
ALTER TABLE users_new RENAME TO users; 