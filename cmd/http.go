package cmd

import (
	"context"
	"github.com/maurofran/kernel/server"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
)

var grpcCmd = &cobra.Command{
	Use:   "http",
	Short: "Start the HTTP server",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup

		/*
				driver, dsn := dbConfig()
				redis := redisConfig()
				c, err := container.New(driver, dsn, redis)
				cobra.CheckErr(err)

				if shouldMigrate() {
					slog.Debug("Executing database migrations")

					err = c.Migrate()
					cobra.CheckErr(err)
				}

			forwarder := c.Forwarder()

			go func() {
				wg.Add(1)
				if err := forwarder.Run(ctx); err != nil {
					slog.Error("Unexpected error running forwarder", slog.Any("err", err))
				}
				wg.Done()
			}()
		*/

		go server.RunHTTP(
			ctx,
			&wg,
			func(server *http.ServeMux) {
				slog.Info("Registering routes to HTTP server")
			},
			config.Server,
		)

		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
		<-signalCh
		/*if err := forwarder.Close(); err != nil {
			slog.Error("Unexpected error closing forwarder", slog.Any("err", err))
		}*/
		cancel()
		wg.Wait()

		slog.Info("Shutdown completed")
	},
}

func init() {
	serveCmd.AddCommand(grpcCmd)
}
