package migrate

import (
	"database/sql"
	"embed"
	"github.com/maurofran/kernel/db/migrate"
	"log/slog"
)

//go:embed *.sql
var files embed.FS

// Run executes database migrations using the given SQL database connection and migration configuration settings.
func Run(db *sql.DB, config *migrate.Config) error {
	slog.Debug("Running migrations")

	return migrate.Run(files, db, config)
}
