package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	ssov1 "github.com/j0n1que/sso-protos/gen/go"
	"github.com/j0n1que/sso-service/internal/domain/models"
	"github.com/j0n1que/sso-service/internal/lib/jwt"
	"github.com/j0n1que/sso-service/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log         *slog.Logger
	usrChanger  UserChanger
	usrProvider UserProvider
	tknProvider TokenProvider
	tokenTTL    time.Duration
}

type UserChanger interface {
	SaveUser(ctx context.Context, user models.User) error
	ChangePassword(ctx context.Context, userID int64, newPasswordHash []byte) error
	MakeAdmin(ctx context.Context, userID int64) error
}

type UserProvider interface {
	User(ctx context.Context, login string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	GetAllUsers(ctx context.Context) ([]models.User, error)
	GetUserByTelegram(ctx context.Context, telegramLogin string) ([]models.User, error)
}

type TokenProvider interface {
	JWT(ctx context.Context, userID int64) (string, error)
	SaveJWT(ctx context.Context, token string, userID int64, ttl time.Duration) error
	DeleteJWT(ctx context.Context, userID int64) error
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrTokenExists        = errors.New("token for that user already exists")
	ErrUserNotFound       = errors.New("user not found")
)

func New(log *slog.Logger, userChanger UserChanger, userProvider UserProvider, tokenProvider TokenProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:         log,
		usrChanger:  userChanger,
		usrProvider: userProvider,
		tknProvider: tokenProvider,
		tokenTTL:    tokenTTL,
	}
}

func (a *Auth) RegisterUser(ctx context.Context, login, password, telegramLogin string) error {
	const op = "auth.RegisterUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", slog.String("error", err.Error()))

		return fmt.Errorf("%s: %w", op, err)
	}

	user := models.User{
		Login:         login,
		PassHash:      passHash,
		IsAdmin:       false,
		TelegramLogin: telegramLogin,
	}

	if err := a.usrChanger.SaveUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", slog.String("error", err.Error()))

			return fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", slog.String("error", err.Error()))

		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered")

	return nil
}

func (a *Auth) AuthorizeUser(ctx context.Context, login, password string) (string, error) {
	const op = "auth.AuthorizeUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	log.Info("attempting to authorize user")

	user, err := a.usrProvider.User(ctx, login)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to get user", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	log.Info("user authorized successfully")

	token, err := jwt.NewToken(user, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	if err := a.tknProvider.SaveJWT(ctx, token, user.ID, a.tokenTTL); err != nil {
		if errors.Is(err, storage.ErrTokenExists) {
			log.Warn("token for that user already exists", slog.String("error", err.Error()))
		}
		log.Error("failed to save token", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)

	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}

func (a *Auth) ChangePassword(ctx context.Context, userID int64, newPassword string) error {
	const op = "auth.ChangePassword"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("changing user's password")

	newPassHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate new password hash", slog.String("error", err.Error()))

		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.usrChanger.ChangePassword(ctx, userID, newPassHash); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))

			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to change user's password", slog.String("error", err.Error()))

		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user's password changed")

	return nil
}

func (a *Auth) GetUserByTelegram(ctx context.Context, telegramLogin string) ([]*ssov1.User, error) {
	const op = "auth.GetUserByTelegram"

	log := a.log.With(
		slog.String("op", op),
		slog.String("telegram_login", telegramLogin),
	)

	log.Info("getting user by telegram login")

	users, err := a.usrProvider.GetUserByTelegram(ctx, telegramLogin)

	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))

			return nil, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to get user", slog.String("error", err.Error()))

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("got all user accounts by login")

	grpcUsers := make([]*ssov1.User, len(users))

	for i, user := range users {
		grpcUsers[i] = &ssov1.User{
			UserId:        user.ID,
			Login:         user.Login,
			Password:      string(user.PassHash),
			IsAdmin:       user.IsAdmin,
			TelegramLogin: user.TelegramLogin,
		}
	}

	return grpcUsers, nil
}

func (a *Auth) GetAllUsers(ctx context.Context) ([]*ssov1.User, error) {
	const op = "auth.GetAllUsers"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("getting all users")

	users, err := a.usrProvider.GetAllUsers(ctx)
	if err != nil {
		log.Error("failed to get all users", slog.String("error", err.Error()))

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully got all users")

	grpcUsers := make([]*ssov1.User, len(users))

	for i, user := range users {
		grpcUsers[i] = &ssov1.User{
			UserId:   user.ID,
			Login:    user.Login,
			Password: string(user.PassHash),
			IsAdmin:  user.IsAdmin,
		}
	}

	return grpcUsers, nil
}

func (a *Auth) MakeAdmin(ctx context.Context, userID int64) error {
	const op = "auth.MakeAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("making user an admin")

	if err := a.usrChanger.MakeAdmin(ctx, userID); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))

			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to make user an admin", slog.String("error", err.Error()))

		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully made user an admin")

	return nil
}

func (a *Auth) GetJWT(ctx context.Context, userID int64) (string, error) {
	const op = "auth.GetJWT"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("getting user's token")

	token, err := a.tknProvider.JWT(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))

			return "", fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to get token", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("token got successfully")

	return token, nil
}

func (a *Auth) DeleteJWT(ctx context.Context, userID int64) error {
	const op = "auth.DeleteJWT"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("deleting token")

	if err := a.tknProvider.DeleteJWT(ctx, userID); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))

			return fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to delete token", slog.String("error", err.Error()))

		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully deleted token")

	return nil
}
