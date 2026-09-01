package main

import (
	"context"
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

func main() {

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

	resetStore := redis.NewResetPassword(rdb)
	tokenManager := security.NewTokenManager()
	hasher := argon2.NewArgon2Hasher()
	accountAuditRepo := repository.NewAccountEventAuditStruct(db)
	loginAudit := repository.SessionAndAudit{Database: db}

	mux := http.NewServeMux()

	repositoryRegister := repository.NewRegisterStruct(db)
	serviceRegister := auth.NewRegisterService(repositoryRegister, hasher)
	handlerRegister := handlers.NewRegisterHanlder(serviceRegister)

	repositoryLogin := repository.NewMySQLUserRepository(db)
	serviceLogin := auth.NewLoginService(repositoryLogin, hasher, resetStore, domain.LoginAttemptsAudit{}, loginAudit, &repository.UserSessionStruct{Database: db}, accountAuditRepo)
	handlerLogin := handlers.NewLoginHandler(serviceLogin, limiter)

	repositoryChangeName := repository.NewChangeNameStruct(db)
	serviceChangeName := user.NewChangeNameService(repositoryChangeName)
	handlerChangeName := handlers.NewChangeNameHandler(serviceChangeName)

	repositoryChangeEmail := repository.NewChangeEmailStruct(db)
	serviceChangeEmail := user.NewChangeEmailService(repositoryChangeEmail, hasher, accountAuditRepo)
	handlerChangeEmail := handlers.NewChangeEmailHandler(serviceChangeEmail)

	repositoryRequestResetPassword := repository.NewRequestStruct(db)
	serviceRequestResetPassword := user.NewRequestResetService(repositoryRequestResetPassword, resetStore, tokenManager, notification.NewConsoleNotificationService(), accountAuditRepo)
	handlerRequestResetPassword := handlers.NewRequestHandler(serviceRequestResetPassword, limiter)

	serviceValidCode := auth.NewValidToken(resetStore, tokenManager)
	handlerValidToken := handlers.NewValidTokenHandler(serviceValidCode)

	repositoryResetPassword := repository.NewResetPasswordStruct(db)
	serviceResetPassword := user.NewResetPasswordService(repositoryResetPassword, tokenManager, hasher, resetStore, accountAuditRepo)
	handlerResetPassword := handlers.NewResetPasswordHandler(serviceResetPassword)

	repositoryDeleteAccount := repository.NewDeleteAccountStruct(db)
	serviceDeleteAccount := user.NewDeleteAccountService(repositoryDeleteAccount, hasher)
	handlerDeleteAccount := handlers.NewDeleteAccountHandler(serviceDeleteAccount)

	repositoryChangePassword := repository.NewChangePasswordStruct(db)
	serviceChangePassword := user.NewChangePasswordService(repositoryChangePassword, hasher)
	handlerChangePassword := handlers.NewChangePasswordHandler(serviceChangePassword)

	mux.HandleFunc("/register", handlerRegister.RegisterHandler)
	mux.HandleFunc("/login", handlerLogin.HandlerLogin)

	mux.Handle("/change/name", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerChangeName.ChangeNameHandler)))
	mux.Handle("/change/email", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerChangeEmail.ChangeEmailHandler)))
	mux.Handle("/change/password", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerChangePassword.ChangePasswordHandler)))

	mux.Handle("/delete", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerDeleteAccount.DeleteAccountHandler)))

	mux.HandleFunc("/request", handlerRequestResetPassword.RequestReset)
	mux.HandleFunc("/verify-code", handlerValidToken.ValidToken)

	mux.Handle("/reset/password", middleware.AuthMiddleware(jwtKey, resetStore)(http.HandlerFunc(handlerResetPassword.ResetPasswordHandler)))

	appHandler := middleware.TraceID(mux)
	appHandler = middleware.Recovery(appHandler)
	appHandler = middleware.CorsMiddleware(appHandler)
	appHandler = middleware.SecurityMiddleware(appHandler)
	appHandler = middleware.MetricsMiddleware(appHandler)

	slog.Info("server started", "addr", "127.0.0.1:8000")
	if err := http.ListenAndServe("127.0.0.1:8000", appHandler); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
