package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSecretKey(t *testing.T) {
	key1 := GenerateSecretKey()
	assert.NotEqual(t, "", key1)

	key2 := GenerateSecretKey()
	assert.NotEqual(t, key2, key1)
}
