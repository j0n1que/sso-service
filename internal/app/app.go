package app

import (
	"context"
	"log/slog"
	"time"

	grpcapp "github.com/j0n1que/sso-service/internal/app/grpc"
	"github.com/j0n1que/sso-service/internal/services/auth"
	mongodb "github.com/j0n1que/sso-service/internal/storage/mongo"
	"github.com/j0n1que/sso-service/internal/storage/redis"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type App struct {
	GRPCSrv  *grpcapp.App
	MongoSrv *mongo.Client
	RedisSrv *redis.TokenStorage
}

type TokensStorage struct {
	Addr     string
	Password string
}

func New(ctx context.Context, log *slog.Logger, grpcPort int, userStorageCredentials string, tokenStorageCredentials TokensStorage, tokenTTL time.Duration) *App {
	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(userStorageCredentials))
	if err != nil {
		panic("no connection to mongodb" + err.Error())
	}

	userDAO := mongodb.New(ctx, mongoClient)

	if err := userDAO.EnsureIndexes(ctx); err != nil {
		panic("failed to set indexation for users database" + err.Error())
	}

	redisclient := redis.New(tokenStorageCredentials.Addr, tokenStorageCredentials.Password)

	authService := auth.New(log, userDAO, userDAO, redisclient, tokenTTL)

	grpcApp := grpcapp.New(log, grpcPort, authService, redisclient, userDAO)
	return &App{
		GRPCSrv:  grpcApp,
		MongoSrv: mongoClient,
		RedisSrv: redisclient,
	}
}
