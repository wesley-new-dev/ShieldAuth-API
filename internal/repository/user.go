package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"ShieldAuth-API/internal/domain"

	"github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
)


type RegisterStruct struct {
	Database *sql.DB
}
type MySQLUserRepository struct {
	Database *sql.DB
}
type ChangeNameStruct struct {
	Database *sql.DB
}
type ChangeEmailStruct struct {
	Database *sql.DB
}
type RequestStruct struct {
	Database *sql.DB
}
type ResetPasswordStruct struct {
	Database *sql.DB
	redis *redis.Client
}
type DeleteAccountStruct struct {
	Database *sql.DB
}
type SessionAndAudit struct {
	Database *sql.DB
}
type ChangePasswordStruct struct {
	Database *sql.DB
}
type LogOutStruct struct {
	Database *sql.DB
}


func NewRegisterStruct(database *sql.DB) *RegisterStruct {
	return &RegisterStruct{
		Database: database,
	}
}
func NewMySQLUserRepository(database *sql.DB) *MySQLUserRepository {
	return &MySQLUserRepository{
		Database: database,
	}
}
func NewChangeNameStruct(database *sql.DB) *ChangeNameStruct {
	return &ChangeNameStruct{
		Database: database,
	}
}
func NewChangeEmailStruct(database *sql.DB) *ChangeEmailStruct {
	return &ChangeEmailStruct{
		Database: database,
	}
}
func NewRequestStruct(database *sql.DB) *RequestStruct {
	return &RequestStruct{
		Database: database,
	}
}
func NewResetPasswordStruct(database *sql.DB) *ResetPasswordStruct {
	return &ResetPasswordStruct{
		Database: database,
	}
}
func NewDeleteAccountStruct(database *sql.DB) *DeleteAccountStruct {
	return &DeleteAccountStruct{
		Database: database,
	}
}
func NewChangePasswordStruct(database *sql.DB) *ChangePasswordStruct {
	return &ChangePasswordStruct{
		Database: database,
	}
}
func NewLogOutStruct(database *sql.DB) *LogOutStruct {
	return &LogOutStruct{
		Database: database,
	}
}


func (register *RegisterStruct) Create(ctx context.Context, u *domain.User) (int64, error) {
	result, err := register.Database.ExecContext(ctx, "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", u.Name, u.Email, u.PasswordHash)
	if err != nil {
		if mySqlError, ok := errors.AsType[*mysql.MySQLError](err); ok {
			if mySqlError.Number == 1062 {
				return 0, domain.ErrEmailAlreadyExists
			}
		}
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return id, nil
}


func (r *RegisterStruct) SaveRefreshToken(ctx context.Context, model domain.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`
	result, err := r.Database.ExecContext(ctx, query, model.UserID, model.Token, model.ExpiresAt)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return nil
}


func (r *MySQLUserRepository) GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error) {
	var dbUser struct {
		ID 				int64
		Name 			string
		Email 			string
		PasswordHash 	[]byte
	}

	query := "SELECT id, name, email, password_hash FROM users WHERE name = ? OR email = ? LIMIT 1"
	err := r.Database.QueryRowContext(ctx, query, identifier, identifier).Scan(&dbUser.ID, &dbUser.Name, &dbUser.Email, &dbUser.PasswordHash)
	if err != nil {	
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return domain.RestoreUser(dbUser.ID, dbUser.Name, dbUser.Email, dbUser.PasswordHash), nil
}


func (r *MySQLUserRepository) Rehash(ctx context.Context, id int64, hash []byte) error {
	query := "UPDATE users SET password_hash = ? WHERE id = ?"
	result, err := r.Database.ExecContext(ctx, query, hash, id)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return nil
}


func (r *MySQLUserRepository) SaveRefreshToken(ctx context.Context, model domain.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)` // parece que salva o token em texto puro ao inves do hash por causa do 'model.Token'
	result, err := r.Database.ExecContext(ctx, query, model.UserID, model.Token, model.ExpiresAt)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return nil
}


func (r *ChangeNameStruct) GetForChangeName(ctx context.Context, id int) (*domain.User, error) {
	var result struct {
		ID 		int64
		Name 	string
	}
 
	const query = `SELECT id, name FROM users WHERE id = ?`
	err := r.Database.QueryRowContext(ctx, query, id).Scan(&result.ID, &result.Name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return domain.RestoreUser(result.ID, result.Name, "", nil), nil
}


func (changeName *ChangeNameStruct) UpdateName(ctx context.Context, user *domain.User) error {
	query := "UPDATE users SET name = ? WHERE id = ?"
	result, err := changeName.Database.ExecContext(ctx, query, user.Name, user.Id)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return nil
}


func (changeEmail *ChangeEmailStruct) GetID(ctx context.Context, id int) (*domain.User, error) {
	var test struct {
		ID 				int64
		Email 			string
		PasswordHash 	[]byte
	}

	query := "SELECT id, email, password_hash FROM users WHERE id = ?"
	err := changeEmail.Database.QueryRowContext(ctx, query, id).Scan(&test.ID, &test.Email, &test.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	
	return domain.RestoreUser(test.ID, "", test.Email, test.PasswordHash), nil
}


func (changeEmail *ChangeEmailStruct) UpdateEmail(ctx context.Context, user *domain.User) error {
	query := "UPDATE users SET email = ? WHERE id = ?"
	result, err := changeEmail.Database.ExecContext(ctx, query, user.Email, user.Id)

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return err
}


func(r *RequestStruct) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user := &domain.User{}

	err := r.Database.QueryRowContext(ctx, `SELECT id, email FROM users WHERE email = ?`, email).Scan(&user.Id, &user.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}


func (deleteAccount *DeleteAccountStruct) Delete(ctx context.Context, id int) error {

	result, err := deleteAccount.Database.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return nil
}


func (deleteAccount *DeleteAccountStruct) GetHashById(ctx context.Context, id int) (*domain.User, error) {
	var result struct {
		Id 				int64
		passwordHash 	[]byte
	}
	query := "SELECT id, password_hash FROM users WHERE id = ?"
	err := deleteAccount.Database.QueryRowContext(ctx, query, id).Scan(&result.Id, &result.passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return domain.RestoreUser(result.Id, "", "", result.passwordHash), nil
}


func (r *ResetPasswordStruct) UpdatePassword(ctx context.Context, userID string, passwordHash []byte) error {
	result, err := r.Database.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return nil
}


func (s *SessionAndAudit) InsertIntoLoginAudits(ctx context.Context, email string, success bool, failureReason string) error {
	_, err := s.Database.ExecContext(ctx, `INSERT INTO login_attempts_audit (email, success, failure_reason, attempted_at) VALUES (?, ?, ?, NOW())`, email, success, failureReason)
	if err != nil {
		return fmt.Errorf("insert login audit failed: %w", err)
	}

	return nil
}


func (s *SessionAndAudit) CreateSession(ctx context.Context, userID int, refreshTokenHash string) error {
	_, err := s.Database.ExecContext(ctx, `INSERT INTO sessions (user_id, refresh_token_hash, revoked, expires_at, created_at) VALUES (?, ?, false, DATE_ADD(NOW(), INTERNAL 7 DAY), NOW())`, userID, refreshTokenHash)
	return err
}


func (changePassword *ChangePasswordStruct) FindById(ctx context.Context, id int) (*domain.User, error) {
	var result struct {
		ID 				int64
		PasswordHash 	[]byte
	}

	query := `SELECT id, password_hash FROM users WHERE id = ?`
	err := changePassword.Database.QueryRowContext(ctx, query, id).Scan(&result.ID, &result.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	
	return domain.RestoreUser(result.ID, "", "", result.PasswordHash), nil
}


func (changePassword *ChangePasswordStruct) UpdatePasswordHash(ctx context.Context, id int, hash []byte) error {
	query := `UPDATE users SET password_hash = ? WHERE id = ?`
	result, err := changePassword.Database.ExecContext(ctx, query, hash, id)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}

	return nil
}


func (logout *LogOutStruct) Revoke(ctx context.Context, token_hash []byte) error {
	query := `UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ? AND revoked_at IS NULL`
	result, err := logout.Database.ExecContext(ctx, query, token_hash)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected != 1 {
		return domain.ErrNotFound
	}


	return nil
}