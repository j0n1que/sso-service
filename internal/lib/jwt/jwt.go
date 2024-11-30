package jwt

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/j0n1que/sso-service/internal/domain/models"
)

func NewToken(user models.User, duration time.Duration) (string, error) {
	secret := os.Getenv("SECRET")

	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["login"] = user.Login
	claims["exp"] = time.Now().Add(duration)

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
