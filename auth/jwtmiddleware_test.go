package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tizz98/eli/crypto"
)

func TestJWTMiddleware_CheckJWT(t *testing.T) {
	key, err := crypto.GenerateRsaKey()
	require.NoError(t, err)

	m := NewJWTMiddleware(JWTOptions{
		SigningMethod: jwt.SigningMethodRS512,
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return &key.PublicKey, nil
		},
	})

	t.Run("OPTIONS", func(t *testing.T) {
		t.Run("AuthEnabled", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("OPTIONS", "https://example.com", nil)
			m.Options.EnableAuthOnOptions = true

			require.Error(t, m.CheckJWT(w, req))
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})

		t.Run("AuthDisabled", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("OPTIONS", "https://example.com", nil)
			m.Options.EnableAuthOnOptions = false

			require.NoError(t, m.CheckJWT(w, req))
			assert.Equal(t, http.StatusOK, w.Code)
		})
	})

	t.Run("OptionalCredentials", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "https://example.com", nil)
		m.Options.CredentialsOptional = true

		require.NoError(t, m.CheckJWT(w, req))
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RequiredCredentials", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "https://example.com", nil)
		m.Options.CredentialsOptional = false

		require.Error(t, m.CheckJWT(w, req))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("ValidToken", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "https://example.com", nil)
		m.Options.CredentialsOptional = false

		token, err := NewJWTWithClaims(jwt.MapClaims{}, key)
		require.NoError(t, err)

		req.Header.Set("Authorization", fmt.Sprintf("bearer %s", token))

		require.NoError(t, m.CheckJWT(w, req))
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("InValidToken", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "https://example.com", nil)
		m.Options.CredentialsOptional = false

		req.Header.Set("Authorization", "123")

		require.Error(t, m.CheckJWT(w, req))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestFromAuthHeader(t *testing.T) {
	t.Run("TokenSet", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Authorization", "bearer 123")

		token, err := FromAuthHeader(req)
		require.NoError(t, err)

		assert.Equal(t, "123", token)
	})

	t.Run("TokenNotSet", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Authorization", "")

		token, err := FromAuthHeader(req)
		require.NoError(t, err)

		assert.Equal(t, "", token)
	})

	t.Run("InvalidHeaderLength", func(t *testing.T) {
		t.Run("TooShort", func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://example.com", nil)
			req.Header.Set("Authorization", "bearer")

			token, err := FromAuthHeader(req)
			require.Error(t, err)
			assert.Equal(t, "", token)
		})

		t.Run("TooLong", func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://example.com", nil)
			req.Header.Set("Authorization", "bearer 123 456")

			token, err := FromAuthHeader(req)
			require.Error(t, err)
			assert.Equal(t, "", token)
		})
	})
}

func TestFromParameter(t *testing.T) {
	t.Run("Set", func(t *testing.T) {
		ex := FromParameter("token")
		req := httptest.NewRequest("GET", "https://example.com?token=123", nil)

		token, err := ex(req)
		require.NoError(t, err)
		assert.Equal(t, "123", token)
	})

	t.Run("UnSet", func(t *testing.T) {
		ex := FromParameter("token")
		req := httptest.NewRequest("GET", "https://example.com", nil)

		token, err := ex(req)
		require.NoError(t, err)
		assert.Equal(t, "", token)
	})
}

func TestFromFirst(t *testing.T) {
	t.Run("Extractors", func(t *testing.T) {
		ex := FromFirst(FromParameter("token"), FromAuthHeader)
		req := httptest.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("Authorization", "bearer 123")

		token, err := ex(req)
		require.NoError(t, err)
		assert.Equal(t, "123", token)
	})

	t.Run("NoExtractors", func(t *testing.T) {
		ex := FromFirst()
		req := httptest.NewRequest("GET", "https://example.com", nil)

		token, err := ex(req)
		require.NoError(t, err)
		assert.Equal(t, "", token)
	})
}
