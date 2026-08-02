CREATE TABLE IF NOT EXISTS login_attempts_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    email VARCHAR(120) NOT NULL,
    user_agent VARCHAR(255),
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_email_attempted_at(email, attempted_at),
    INDEX idx_success(success)
);