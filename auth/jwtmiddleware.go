// Inspired by https://github.com/auth0/go-jwt-middleware

package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// A function called whenever an error is encountered
type errorHandler func(w http.ResponseWriter, r *http.Request, err string)

// TokenExtractor is a function that takes a request as input and returns
// either a token or an error.  An error should only be returned if an attempt
// to specify a token was found, but the information was somehow incorrectly
// formed.  In the case where a token is simply not present, this should not
// be treated as an error.  An empty string should be returned in that case.
type TokenExtractor func(r *http.Request) (string, error)

type JWTOptions struct {
	ValidationKeyGetter jwt.Keyfunc
	// Whether the lack of credentials should throw an error
	CredentialsOptional bool
	// Function to be called when there's an error validating the token
	ErrorHandler errorHandler
	// A function to extract the token from the request
	Extractor TokenExtractor
	// When set, all requests with the OPTIONS method will use authentication
	EnableAuthOnOptions bool
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
	SigningMethod jwt.SigningMethod
}

type JWTMiddleware struct {
	Options JWTOptions
}

func OnError(w http.ResponseWriter, r *http.Request, err string) {
	http.Error(w, err, http.StatusUnauthorized)
}

func NewJWTMiddleware(options ...JWTOptions) *JWTMiddleware {
	var opts JWTOptions
	if len(options) == 0 {
		opts = JWTOptions{}
	} else {
		opts = options[0]
	}

	if opts.ErrorHandler == nil {
		opts.ErrorHandler = OnError
	}

	if opts.Extractor == nil {
		opts.Extractor = FromAuthHeader
	}

	if opts.SigningMethod == nil {
		panic("signing method must be set")
	}

	return &JWTMiddleware{opts}
}

func (m *JWTMiddleware) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := m.CheckJWT(w, r); err != nil {
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

// FromParameter returns a function that extracts the token from the specified
// query string parameter
func FromParameter(param string) TokenExtractor {
	return func(r *http.Request) (string, error) {
		return r.URL.Query().Get(param), nil
	}
}

// FromFirst returns a function that runs multiple token extractors and takes the
// first token it finds
func FromFirst(extractors ...TokenExtractor) TokenExtractor {
	return func(r *http.Request) (string, error) {
		for _, ex := range extractors {
			token, err := ex(r)
			if err != nil {
				return "", err
			}
			if token != "" {
				return token, nil
			}
		}
		return "", nil
	}
}

func (m *JWTMiddleware) CheckJWT(w http.ResponseWriter, r *http.Request) error {
	if !m.Options.EnableAuthOnOptions {
		if r.Method == "OPTIONS" {
			return nil
		}
	}

	token, err := m.Options.Extractor(r)
	if err != nil {
		m.Options.ErrorHandler(w, r, err.Error())
		return errors.Wrap(err, "error extracting token")
	}

	if token == "" {
		if m.Options.CredentialsOptional {
			return nil
		}

		m.Options.ErrorHandler(w, r, "Required authorization token not found")
		return fmt.Errorf("required authorization token not found")
	}

	parsed, err := jwt.Parse(token, m.Options.ValidationKeyGetter)
	if err != nil {
		m.Options.ErrorHandler(w, r, err.Error())
		return errors.Wrap(err, "error parsing token")
	}

	if m.Options.SigningMethod != nil && m.Options.SigningMethod.Alg() != parsed.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s", m.Options.SigningMethod.Alg(), parsed.Header["alg"])
		m.Options.ErrorHandler(w, r, message)
		return fmt.Errorf(message)
	}

	if !parsed.Valid {
		m.Options.ErrorHandler(w, r, "The token is not valid")
		return fmt.Errorf("invalid token")
	}

	*r = *r.WithContext(context.WithValue(r.Context(), jwtContextKey, parsed))
	return nil
}
