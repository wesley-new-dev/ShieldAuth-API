ALTER TABLE refresh_token
DROP FOREIGN KEY fk_refresh_token_replaced;

ALTER TABLE
DROP INDEX uk_refresh_token_hash;

ALTER TABLE refresh_token
DROP INDEX idx_expires_at;

ALTER TABLE refresh_token
DROP COLUMN replaced_by_token_id;

ALTER TABLE refresh_token
DROP COLUMN session_id;

ALTER TABLE refresh_token
DROP COLUMN last_used_at;

ALTER TABLE refresh_token
DROP COLUMN revoked_at;