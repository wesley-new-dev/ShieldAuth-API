ALTER TABLE refresh_tokens
DROP FOREIGN KEY fk_refresh_token_replaced;

ALTER TABLE refresh_tokens
DROP INDEX uk_refresh_token_hash;

ALTER TABLE refresh_tokens
DROP INDEX idx_expires_at;

ALTER TABLE refresh_tokens
DROP COLUMN replaced_by_token_id;

ALTER TABLE refresh_tokens
DROP COLUMN session_id;

ALTER TABLE refresh_tokens
DROP COLUMN last_used_at;

ALTER TABLE refresh_tokens
CHANGE revoked_at revoked BOOLEAN NOT NULL DEFAULT FALSE;