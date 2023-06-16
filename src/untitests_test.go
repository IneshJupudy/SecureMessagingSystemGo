package main

import (
	"crypto/x509"
	"testing"
	"os"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	privateKey, publicKeyBytes := generateRSAKeyPair()

	// Check if the private key is not nil
	assert.NotNil(t, privateKey)

	// Check if the public key bytes are not empty
	assert.NotEmpty(t, publicKeyBytes)

	// Parse the public key bytes and check for errors
	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBytes)
	assert.NoError(t, err)

	// Check if the parsed public key matches the one from the private key
	assert.Equal(t, &privateKey.PublicKey, publicKey)
}

func TestGenerateAndEncryptSharedKey(t *testing.T) {
	privateKey, publicKeyBytes := generateRSAKeyPair()

	// Check if the private key is not nil
	assert.NotNil(t, privateKey)

	// Check if the public key bytes are not empty
	assert.NotEmpty(t, publicKeyBytes)

	encryptedSharedKey, sharedKey := generateAndEncryptSharedKey(publicKeyBytes)

	// Check if the encrypted shared key is not nil
	assert.NotNil(t, encryptedSharedKey)

	// Check if the shared key is not empty
	assert.NotEmpty(t, sharedKey)
}

func TestKeyExchange(t *testing.T) {
	privateKey, publicKeyBytes := generateRSAKeyPair()
	encryptedSharedKey, plainTextSharedKey := generateAndEncryptSharedKey(publicKeyBytes)
	decryptedSharedKey := decryptSharedKey(encryptedSharedKey, privateKey)
	assert.Equal(t, decryptedSharedKey, plainTextSharedKey, "The 2 keys don't match")
}

func TestEncryptionAndDecryption(t *testing.T) {
	privateKey, publicKeyBytes := generateRSAKeyPair()
	encryptedSharedKey, plainTextSharedKey := generateAndEncryptSharedKey(publicKeyBytes)
	decryptedSharedKey := decryptSharedKey(encryptedSharedKey, privateKey)
	assert.Equal(t, decryptedSharedKey, plainTextSharedKey, "The 2 keys don't match")

	sampleMessage := []byte("This is a sample text!")
	encryptedMessage, _ := encryptMessage(sampleMessage, plainTextSharedKey)
	decryptedMessage, _ := decryptMessage(encryptedMessage, plainTextSharedKey)
	assert.Equal(t, sampleMessage, decryptedMessage, "The 2 messages don't match")

}

// Add more unit tests for other functions in your code...
func TestMain(m *testing.M) {
	// Run the tests
	os.Exit(m.Run())
}
