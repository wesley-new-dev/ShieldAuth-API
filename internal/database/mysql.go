package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/joho/godotenv"
)

func Connect() *sql.DB {
	err := godotenv.Load()
	if err != nil {
		slog.Error("failed to load environment variables", "error", err)
		os.Exit(1)
	}

	databaseUser := os.Getenv("DATABASE_USER")
	databasePassword := os.Getenv("DATABASE_PASSWORD")
	databaseName := os.Getenv("DATABASE_NAME")
	databaseHost := os.Getenv("DATABASE_HOST")
	databasePort := os.Getenv("DATABASE_PORT")

	dataSourceTime := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?multiStatements=true", databaseUser, databasePassword, databaseHost, databasePort, databaseName)

	var database *sql.DB

	for i := range 5 {
		database, err = sql.Open("mysql", dataSourceTime)
		if err == nil {
			err = database.Ping()
			if err == nil {
				database.SetMaxOpenConns(10)
				database.SetMaxIdleConns(5)
				database.SetConnMaxLifetime(5 * time.Minute)
				return database
			}
		}

		slog.Info("waiting for database connection", "attempt", i+1, "max_attempts", 10)
		time.Sleep(3 * time.Second)
	}

	slog.Error("failed to connect to database", "error", err)
	os.Exit(1)
	return nil
}

func RunMigrations(db *sql.DB) {
	driver, err := mysql.WithInstance(db, &mysql.Config{})
	if err != nil {
		slog.Error("failed to create migration driver", "error", err)
		os.Exit(1)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://internal/database/migrations",
		"mysql",
		driver,
	)
	if err != nil {
		slog.Error("failed to create migrate instance", "error", err)
		os.Exit(1)
	}

	versionBefore, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		slog.Error("failed to read migration version", "error", err)
		os.Exit(1)
	}
	if dirty {
		slog.Info("dirty migration state detected", "version", versionBefore)
	}

	err = m.Up()
	if err != nil {
		if err == migrate.ErrNoChange {
			slog.Info("no new migrations to run", "current_version", versionBefore)
			return
		}
		slog.Error("failed to apply migrations", "error", err)
		os.Exit(1)
	}

	versionAfter, _, _ := m.Version()
	slog.Info("migration applied", "from_version", versionBefore, "to_version", versionAfter)
}
