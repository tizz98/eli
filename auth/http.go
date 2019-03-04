package auth

import (
	"context"

	"github.com/dgrijalva/jwt-go"
)

type contextKey struct {
	name string
}

var jwtContextKey = &contextKey{"jwt"}

func JWTFromContext(ctx context.Context) *jwt.Token {
	if token, ok := ctx.Value(jwtContextKey).(*jwt.Token); ok {
		return token
	}
	return nil
}
