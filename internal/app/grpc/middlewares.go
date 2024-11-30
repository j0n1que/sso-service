package grpcapp

import (
	"context"
	"errors"

	"github.com/j0n1que/sso-service/internal/domain/models"
	"github.com/j0n1que/sso-service/internal/storage"
	"github.com/j0n1que/sso-service/internal/storage/mongo"
	"github.com/j0n1que/sso-service/internal/storage/redis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthMiddleware struct {
	tokenStorage *redis.TokenStorage
	userStorage  *mongo.UserDAO
}

func NewAuthMiddleware(tokenStorage *redis.TokenStorage, userStorage *mongo.UserDAO) *AuthMiddleware {
	return &AuthMiddleware{
		tokenStorage: tokenStorage,
		userStorage:  userStorage,
	}
}

func (am *AuthMiddleware) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	publicMethods := map[string]bool{
		"/Auth/RegisterNewUser": true,
		"/Auth/AuthorizeUser":   true,
	}

	md, flag := metadata.FromIncomingContext(ctx)
	if !flag {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	telegramLogin := md.Get("telegramLogin")
	if len(telegramLogin) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing login in header")
	}

	users, err := am.userStorage.GetUserByTelegram(ctx, telegramLogin[0])
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) && info.FullMethod == "/Auth/RegisterNewUser" {
			return handler(ctx, req)
		}
		return nil, status.Errorf(codes.Unauthenticated, "user with such telegram login not found: %v", err)
	}

	userID := am.findSesion(ctx, users)
	if userID == -1 {
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		return nil, status.Errorf(codes.Unauthenticated, "missing user")
	}

	if publicMethods[info.FullMethod] {
		return nil, status.Errorf(codes.PermissionDenied, "access denied for authenticated users")
	}

	isAdmin, err := am.userStorage.IsAdmin(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error checking admin status: %v", err)
	}

	if isAdmin {
		return handler(ctx, req)
	}

	if info.FullMethod == "/Auth/ChangePassword" {
		return handler(ctx, req)
	}

	return nil, status.Errorf(codes.PermissionDenied, "access denied")
}

func (am *AuthMiddleware) findSesion(ctx context.Context, users []models.User) int64 {
	for i := range users {
		uid := users[i].ID
		_, err := am.tokenStorage.JWT(ctx, uid)
		if err == nil {
			return uid
		}
	}
	return -1
}
