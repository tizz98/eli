package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var key = []byte("o4H845smMQNOOXmELqpAClvsW5dDVEJa")

func TestEncrypt(t *testing.T) {
	encrypted, err := Encrypt([]byte("foo"), key)
	require.NoError(t, err)

	assert.NotEqual(t, "foo", string(encrypted))
}

func TestDecrypt(t *testing.T) {
	encrypted, err := Encrypt([]byte("foo"), key)
	require.NoError(t, err)

	decrypted, err := Decrypt(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, "foo", string(decrypted))
}
