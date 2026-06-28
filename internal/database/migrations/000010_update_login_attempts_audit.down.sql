ALTER TABLE login_attempts_audit
DROP FOREIGN KEY fk_login_attempts_user;

ALTER TABLE login_attempts_audit
MODIFY COLUMN id INT AUTO_INCREMENT,
MODIFY COLUMN user_agent VARCHAR(255),
CREATE INDEX idx_success ON login_attempts_audit(success),
ADD CONSTRAINT login_attempts_audit_ibfk_1
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;