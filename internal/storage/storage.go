package storage

import "errors"

var (
	ErrUserExists    = errors.New("user already exists")
	ErrTokenExists   = errors.New("token for that user already exists")
	ErrUserNotFound  = errors.New("user not found")
	ErrTokenNotFound = errors.New("token for that user not found")
)
