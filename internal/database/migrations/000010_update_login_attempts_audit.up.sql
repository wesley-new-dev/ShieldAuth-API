ALTER TABLE login_attempts_audit
DROP FOREIGN KEY login_attempts_audit_ibfk_1;

ALTER TABLE login_attempts_audit
MODIFY COLUMN id BIGINT AUTO_INCREMENT,
MODIFY COLUMN user_agent TEXT,
DROP INDEX idx_success,
ADD CONSTRAINT fk_login_attempts_user
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;