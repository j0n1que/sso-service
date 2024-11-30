package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/j0n1que/sso-service/internal/app"
	"github.com/j0n1que/sso-service/internal/config"
)

const (
	envLocal = "local"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("starting service")

	ctx := context.TODO()

	application := app.New(ctx, log, cfg.GRPC.Port, cfg.UsersStorage, app.TokensStorage{
		Addr:     cfg.TokensStorage.Addr,
		Password: cfg.TokensStorage.Password,
	}, cfg.TokenTTL)

	go func() {
		application.GRPCSrv.MustRun()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop

	log.Info("stopping service", slog.String("signal", sign.String()))
	application.RedisSrv.Close()
	application.MongoSrv.Disconnect(ctx)
	application.GRPCSrv.Stop()

	log.Info("service stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}
	return log
}
