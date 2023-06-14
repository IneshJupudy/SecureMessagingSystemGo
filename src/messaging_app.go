package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"io/ioutil"
	"log"
	"encoding/pem"
	"errors"
	"crypto/sha256"
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
	sharedKey, err := rsa.EncryptPKCS1v15(rand.Reader, &rsa.PublicKey{N: rsaPublicKey.N, E: rsaPublicKey.E}, []byte("shared key"))
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