package app

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"

	"ShieldAuth-API/internal/database"
	"ShieldAuth-API/internal/domain"
	"ShieldAuth-API/internal/handlers"
	"ShieldAuth-API/internal/middleware"
	"ShieldAuth-API/internal/notification"
	"ShieldAuth-API/internal/repository"
	"ShieldAuth-API/internal/security"
	"ShieldAuth-API/internal/security/argon2"
	"ShieldAuth-API/internal/security/redis"
	"ShieldAuth-API/internal/service/auth"
	"ShieldAuth-API/internal/service/user"

	"github.com/joho/godotenv"
	goredis "github.com/redis/go-redis/v9"
)

type Config struct {
	Database *sql.DB
	Router   http.Handler
}

func NewConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		slog.Warn(".env file was not found", "error", err)
	}

	jwtKey := os.Getenv("JWT_KEY")
	redisAddr := os.Getenv("REDIS_ADDR")

	limiter, err := redis.NewRedisLimiter(redisAddr)
	if err != nil {
		slog.Error("error connecting to Redis", "error", err, "redis_addr", redisAddr)
		os.Exit(1)
	}

	db := database.Connect()
	defer db.Close()
	database.RunMigrations(db)

	rdb := goredis.NewClient(&goredis.Options{Addr: redisAddr, DB: 0})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		slog.Error("redis ping failed", "error", err, "redis_addr", redisAddr)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	resetStore := redis.NewResetPassword(rdb)
	tokenManager := security.NewTokenManager()
	hasher := argon2.NewArgon2Hasher()
	userRepository := repository.NewUserRepositoryStruct(db)
	accountAuditRepo := userRepository
	loginAudit := repository.NewLoginAuditRepository(userRepository)
	passwordHistory := repository.NewPasswordHistoryRepository(userRepository)
	repositoryUserSession := repository.NewUserSessionRepository(userRepository)
	saveRefreshTokens := userRepository
	passwordResetRecord := repository.NewResetPasswordRecordRepository(userRepository)

	serviceRegister := auth.NewRegisterService(userRepository, hasher, saveRefreshTokens)
	handlerRegister := handlers.NewRegisterHandler(serviceRegister)

	serviceLogin := auth.NewLoginService(userRepository, hasher, resetStore, domain.LoginAttemptsAudit{}, loginAudit, repositoryUserSession, accountAuditRepo, saveRefreshTokens)
	handlerLogin := handlers.NewLoginHandler(serviceLogin, limiter)

	serviceChangeName := user.NewChangeNameService(userRepository)
	handlerChangeName := handlers.NewChangeNameHandler(serviceChangeName)

	serviceChangeEmail := user.NewChangeEmailService(userRepository, hasher, accountAuditRepo)
	handlerChangeEmail := handlers.NewChangeEmailHandler(serviceChangeEmail)

	serviceRequestResetPassword := user.NewRequestResetService(userRepository, resetStore, notification.NewConsoleNotificationService(), accountAuditRepo)
	handlerRequestResetPassword := handlers.NewRequestHandler(serviceRequestResetPassword, limiter)

	serviceValidCode := auth.NewValidToken(resetStore, tokenManager, passwordResetRecord)
	handlerValidToken := handlers.NewValidTokenHandler(serviceValidCode)

	repositoryResetPassword := repository.NewResetPasswordRepository(userRepository)
	serviceResetPassword := user.NewResetPasswordService(repositoryResetPassword, tokenManager, hasher, resetStore, accountAuditRepo, passwordHistory, passwordResetRecord)
	handlerResetPassword := handlers.NewResetPasswordHandler(serviceResetPassword)

	serviceDeleteAccount := user.NewDeleteAccountService(userRepository, hasher)
	handlerDeleteAccount := handlers.NewDeleteAccountHandler(serviceDeleteAccount)

	serviceChangePassword := user.NewChangePasswordService(userRepository, hasher, passwordHistory)
	handlerChangePassword := handlers.NewChangePasswordHandler(serviceChangePassword)

	serviceGetAccount := user.NewGetAccountService(userRepository, repositoryUserSession)
	handlerGetAccount := handlers.NewGetAccountHandler(serviceGetAccount)

	serviceLogout := auth.NewLogOutService(userRepository, resetStore)
	handlerLogout := handlers.NewLogOutHandler(serviceLogout)

	serviceTwoFactor := user.NewTwoFactorService(userRepository, hasher)
	handlerTwoFactor := handlers.NewTwoFactorHandler(serviceTwoFactor)

	mux.HandleFunc("/register", handlerRegister.RegisterHandler)
	mux.HandleFunc("/login", handlerLogin.HandlerLogin)

	mux.Handle("/change/name", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerChangeName.ChangeNameHandler)))
	mux.Handle("/change/email", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerChangeEmail.ChangeEmailHandler)))
	mux.Handle("/change/password", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerChangePassword.ChangePasswordHandler)))

	mux.Handle("/me", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerGetAccount.GetAccountHandler)))

	mux.Handle("/delete", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerDeleteAccount.DeleteAccountHandler)))

	mux.HandleFunc("/request", handlerRequestResetPassword.RequestReset)
	mux.HandleFunc("/reset/password", handlerResetPassword.ResetPasswordHandler)

	mux.HandleFunc("/verify-code", handlerValidToken.ValidToken)
	mux.Handle("/logout", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerLogout.LogOutHandler)))

	mux.Handle("/two-factor", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerTwoFactor.TwoFactorHandler)))

	appHandler := middleware.MetricsMiddleware(mux)
	appHandler = middleware.SecurityMiddleware(appHandler)
	appHandler = middleware.CorsMiddleware(appHandler)
	appHandler = middleware.Recovery(appHandler)
	appHandler = middleware.TraceID(appHandler)

	router := mux

	return &Config{Database: db, Router: router}, nil
}
