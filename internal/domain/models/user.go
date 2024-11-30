package models

type User struct {
	ID            int64  `bson:"_id"`
	Login         string `bson:"login"`
	PassHash      []byte `bson:"passHash"`
	IsAdmin       bool   `bson:"isAdmin"`
	TelegramLogin string `bson:"telegramLogin"`
}
