package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// Functions based on: https://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64

// secretKey should be 16, 24, or 32 bytes
func Encrypt(value, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	b := base64.StdEncoding.EncodeToString(value)
	ciphertext := make([]byte, aes.BlockSize+len(b))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))

	return ciphertext, nil
}

// secretKey should be 16, 24, or 32 bytes
func Decrypt(encryptedValue, secretKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	iv := encryptedValue[:aes.BlockSize]
	encryptedValue = encryptedValue[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(encryptedValue, encryptedValue)
	data, err := base64.StdEncoding.DecodeString(string(encryptedValue))

	if err != nil {
		return nil, err
	}
	return data, nil
}
