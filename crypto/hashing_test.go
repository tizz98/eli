package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComparePasswordHash(t *testing.T) {
	hash, err := GeneratePasswordHash([]byte("foo"))
	require.NoError(t, err)

	assert.True(t, ComparePasswordHash(hash, []byte("foo")))
}

func TestGeneratePasswordHash(t *testing.T) {
	hash, err := GeneratePasswordHash([]byte("foo"))
	require.NoError(t, err)

	assert.NotEqual(t, []byte("foo"), hash)
}
