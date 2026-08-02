ALTER TABLE refresh_tokens
ADD CONSTRAINT uk_refresh_token_hash
UNIQUE (token_hash);

ALTER TABLE refresh_tokens
CHANGE revoked revoked_at DATETIME NULL;

ALTER TABLE refresh_tokens
ADD COLUMN last_used_at DATETIME NULL;

ALTER TABLE refresh_tokens
ADD COLUMN session_id CHAR(36) NOT NULL;

ALTER TABLE refresh_tokens
ADD COLUMN replaced_by_token_id BIGINT UNSIGNED NULL;

ALTER TABLE refresh_tokens
ADD CONSTRAINT fk_refresh_token_replaced
FOREIGN KEY (replaced_by_token_id)
REFERENCES refresh_tokens(id);

ALTER TABLE refresh_tokens
ADD INDEX idx_expires_at (expires_at);