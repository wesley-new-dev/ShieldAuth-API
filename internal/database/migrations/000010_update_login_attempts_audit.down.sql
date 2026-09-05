ALTER TABLE login_attempts_audit
DROP FOREIGN KEY fk_login_attempts_user;

ALTER TABLE login_attempts_audit
MODIFY COLUMN id INT AUTO_INCREMENT,
MODIFY COLUMN user_agent VARCHAR(255),
ADD INDEX idx_success (success),
ADD CONSTRAINT login_attempts_audit_ibfk_1
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;