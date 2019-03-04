package auth

import (
	"crypto/rsa"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func NewJWTWithClaims(claims jwt.MapClaims, key *rsa.PrivateKey) (string, error) {
	claims["nbf"] = time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return token.SignedString(key)
}
