package cmd

import (
	"context"
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/maurofran/auth/internal/ports/adapters/db"
	"github.com/maurofran/auth/internal/ports/adapters/db/migrate"
	"github.com/maurofran/auth/internal/ports/adapters/grpc/iam"
	"github.com/maurofran/auth/internal/ports/adapters/oidc"
	"github.com/maurofran/kernel/server"
	"github.com/spf13/cobra"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var grpcCmd = &cobra.Command{
	Use:   "http",
	Short: "Start the HTTP server",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup

		conn, err := setupDatabase(ctx)
		cobra.CheckErr(err)

		if config.DB.Migrate.Enabled {
			err = migrateDatabase(ctx, conn)
			cobra.CheckErr(err)
		}

		slog.DebugContext(ctx, "Creating repositories")

		authnSessionManager := db.NewAuthnSessionManager(conn)
		clientManager := db.NewClientManager(conn)
		grantSessionManager := db.NewGrantSessionManager(conn)
		sessionStore := db.NewSessionStore(conn)

		slog.DebugContext(ctx, "Creating IAM authentication policy")

		policy, err := iam.Policy(config.Oidc.Issuer, sessionStore, nil)
		cobra.CheckErr(err)

		slog.DebugContext(ctx, "Creating OIDC prvider")

		provider, err := oidc.NewProvider(
			config.Oidc,
			clientManager,
			grantSessionManager,
			authnSessionManager,
			policy,
		)
		cobra.CheckErr(err)

		go server.RunHTTP(
			ctx,
			&wg,
			func(server *http.ServeMux) {
				slog.InfoContext(ctx, "Registering OIDC routes to HTTP server")

				server.Handle("/", provider.Handler())
			},
			config.Server,
		)

		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
		<-signalCh

		cancel()
		wg.Wait()

		slog.Info("Shutdown completed")
	},
}

func setupDatabase(ctx context.Context) (*sql.DB, error) {
	dsn := config.DB.Dsn()

	slog.DebugContext(ctx, "Connecting to database", slog.String("dsn", dsn))

	conn, err := sql.Open(config.DB.Driver, dsn)
	if err != nil {
		return nil, err
	}
	if config.DB.Ping {
		slog.DebugContext(ctx, "Pinging database")

		if err := conn.Ping(); err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func migrateDatabase(ctx context.Context, db *sql.DB) error {
	slog.DebugContext(ctx, "Migrating database")

	return migrate.Run(db, &config.DB.Migrate)
}

func init() {
	serveCmd.AddCommand(grpcCmd)
}
