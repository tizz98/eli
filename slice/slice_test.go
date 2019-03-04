package slice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSafeStringCut(t *testing.T) {
	t.Run("Shorter", func(t *testing.T) {
		assert.Equal(t, "123", SafeStringCut("123", 4))
	})

	t.Run("Longer", func(t *testing.T) {
		assert.Equal(t, "1234", SafeStringCut("12345", 4))
	})

	t.Run("Equal", func(t *testing.T) {
		assert.Equal(t, "1234", SafeStringCut("1234", 4))
	})
}
