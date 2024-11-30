package mongo

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/j0n1que/sso-service/internal/domain/models"
	"github.com/j0n1que/sso-service/internal/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserDAO struct {
	c *mongo.Collection
}

func New(ctx context.Context, client *mongo.Client) *UserDAO {
	return &UserDAO{
		c: client.Database("core").Collection("users"),
	}
}

func (dao *UserDAO) SaveUser(ctx context.Context, user models.User) error {
	const op = "storage.mongo.SaveUser"

	user.ID = int64(uuid.New().ID())
	_, err := dao.c.InsertOne(ctx, user)

	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (dao *UserDAO) ChangePassword(ctx context.Context, userID int64, newPasswordHash []byte) error {
	const op = "storage.mongo.ChangePassword"

	user, err := dao.findByID(ctx, userID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	user.PassHash = newPasswordHash

	filter := bson.D{{Key: "_id", Value: userID}}

	_, err = dao.c.ReplaceOne(ctx, filter, user)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (dao *UserDAO) MakeAdmin(ctx context.Context, userID int64) error {
	const op = "storage.mongo.MakeAdmin"

	user, err := dao.findByID(ctx, userID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	user.IsAdmin = true

	filter := bson.D{{Key: "_id", Value: userID}}

	_, err = dao.c.ReplaceOne(ctx, filter, user)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (dao *UserDAO) User(ctx context.Context, login string) (models.User, error) {
	const op = "storage.mongo.User"

	filter := bson.D{{Key: "login", Value: login}}

	var user models.User

	err := dao.c.FindOne(ctx, filter).Decode(&user)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}

func (dao *UserDAO) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.mongo.IsAdmin"

	var user models.User

	user, err := dao.findByID(ctx, userID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}
	return user.IsAdmin, nil
}

func (dao *UserDAO) GetUserByTelegram(ctx context.Context, telegramLogin string) ([]models.User, error) {
	const op = "storage.mongo.GetUserByTelegram"

	filter := bson.D{{Key: "telegramLogin", Value: telegramLogin}}

	cursor, err := dao.c.Find(ctx, filter)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var users []models.User

	for cursor.Next(ctx) {
		var user models.User
		if err := cursor.Decode(&user); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		users = append(users, user)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return users, nil
}

func (dao *UserDAO) GetAllUsers(ctx context.Context) ([]models.User, error) {
	const op = "storage.mongo.GetAllUsers"

	filter := bson.D{}

	cursor, err := dao.c.Find(ctx, filter)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var users []models.User

	for cursor.Next(ctx) {
		var user models.User
		if err := cursor.Decode(&user); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		users = append(users, user)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return users, nil
}

func (dao *UserDAO) EnsureIndexes(ctx context.Context) error {
	const op = "storage.mongo.EnsureIndexes"

	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "login", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "telegramLogin", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	_, err := dao.c.Indexes().CreateMany(ctx, indexModels)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (dao *UserDAO) findByID(ctx context.Context, userID int64) (models.User, error) {
	filter := bson.D{{Key: "_id", Value: userID}}

	var user models.User

	err := dao.c.FindOne(ctx, filter).Decode(&user)

	if err != nil {
		return models.User{}, err
	}
	return user, nil
}
