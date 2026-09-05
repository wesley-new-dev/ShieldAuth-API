ALTER TABLE reset_password
DROP INDEX idx_user_id,
DROP INDEX idx_expires_at,
DROP COLUMN user_agent,
DROP COLUMN consumed_at,
MODIFY used BOOLEAN DEFAULT FALSE,
MODIFY created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
CHANGE token_hash token VARCHAR(255) NOT NULL UNIQUE;

ALTER TABLE users
DROP COLUMN updated_at,
CHANGE password_hash password VARCHAR(150) NOT NULL;

CREATE TABLE IF NOT EXISTS attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(120) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX index_email_time(email, attempted_at)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    email VARCHAR(120) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success TINYINT(1) DEFAULT 0,
    INDEX index_name(name, attempted_at),
    INDEX index_email(email, attempted_at)
);
