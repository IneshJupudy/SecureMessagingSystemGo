package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"io/ioutil"
	"log"
	"fmt"
	"encoding/pem"
	"errors"
	"crypto/sha256"

	"github.com/zenazn/pkcs7pad"
)

func generateRSAKeyPair() (*rsa.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if (err != nil) {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	publicKey := privateKey.PublicKey
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	return privateKey, publicKeyBytes
}

func savePublicKey(publicKeyBytes []byte, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	block := &pem.Block{
		Type: "PUBLIC KEY",
		Headers: nil,
		Bytes: publicKeyBytes,
	}

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

func loadPublicKey(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, errors.New("Failed to decode PEM block")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("Failed to decode PEM block")
	}

	publicKeyBytes := block.Bytes
	return publicKeyBytes, nil
}

func generateAndEncryptSharedKey(publicKey []byte) ([]byte){
	rsaPublicKey, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil
	}
	sharedKey, err := rsa.EncryptPKCS1v15(rand.Reader, &rsa.PublicKey{N: rsaPublicKey.N, E: rsaPublicKey.E}, []byte("shared keyaaaaaa"))
	if err != nil {
		log.Fatal("Failed to perform key exchange:", err)
	}
	return sharedKey
}

func decryptSharedKey(encryptedSharedKey []byte, privateKey *rsa.PrivateKey) ([]byte){
	decryptedKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedSharedKey)
	if err != nil {
		log.Fatal("Failed to decrypt shared key:", err)
	}
	return decryptedKey
}

func performKeyExchange(privateKey *rsa.PrivateKey, receiverPublicKey []byte) []byte {
	//Decrypt receiver's public key
	receiverPublicKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, receiverPublicKey, nil)
	if err != nil {
		log.Fatal("Failed to decrypt receiver's public key:", err)
	}
	return receiverPublicKey
}

//encrypt message with shared key
func encryptMessage(message []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	//pad message to multiple of blocksize
	paddedMessage := pkcs7pad.Pad(message, aes.BlockSize)

	//allocate memory for IV & message
	encrypted := make([]byte, aes.BlockSize+len(paddedMessage))

	//add a random initialization vector
	iv := encrypted[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted[aes.BlockSize:], paddedMessage)

	return encrypted, nil
}

func decryptMessage(encrypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted message is too short")
	}

	//extract the initialization vector
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	//unpad decrypted message using last byte
	decryptedUnpadded, err := pkcs7pad.Unpad(decrypted)

	return decryptedUnpadded, nil
}
