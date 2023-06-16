package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
	"log"
	"fmt"
	"crypto/sha256"
	"sync"
	"time"
	"encoding/json"
	"net/http"
	"bytes"
	"bufio"
	"os"

	"github.com/zenazn/pkcs7pad"
)

type Message struct {
	SenderId	string
	Timestamp  time.Time
	Message  []byte
	MessageType string
}

type HTTPResponse struct {
	ResponseType string
	Response []byte
}

//Decryption Context struct
type DecryptionContext struct {
	mu            sync.Mutex
	decryptionKey []byte
	cond          *sync.Cond
}

func generateRSAKeyPair() (*rsa.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if (err != nil) {
		fmt.Println("Failed to generate RSA key pair:", err)
	}

	publicKey := privateKey.PublicKey
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	return privateKey, publicKeyBytes
}

func generateAndEncryptSharedKey(publicKey []byte) ([]byte, []byte){

	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		fmt.Println("Failed to generate random byte sequence for encryption", err)
		return nil, nil
	}

	rsaPublicKey, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil, nil
	}
	encryptedSharedKey, err := rsa.EncryptPKCS1v15(rand.Reader, &rsa.PublicKey{N: rsaPublicKey.N, E: rsaPublicKey.E}, buf)
	if err != nil {
		fmt.Println("Failed to perform key exchange:", err)
		return nil, nil
	}
	return encryptedSharedKey, buf
}

//decrypt shared key with private key
func decryptSharedKey(encryptedSharedKey []byte, privateKey *rsa.PrivateKey) []byte{
	decryptedKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedSharedKey)
	if err != nil {
		fmt.Println("Failed to decrypt shared key:", err)
	}
	return decryptedKey
}

func performKeyExchange(privateKey *rsa.PrivateKey, receiverPublicKey []byte) []byte {
	//Decrypt receiver's public key
	receiverPublicKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, receiverPublicKey, nil)
	if err != nil {
		fmt.Println("Failed to decrypt receiver's public key:", err)
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

//decrypt message with shared key
func decryptMessage(encrypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
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

func acceptUserInput(wg *sync.WaitGroup, receiverPort string, decryptionContext *DecryptionContext, senderId string) {
	defer wg.Done()
	//check if user wants to close the chat
	var userInput string
	var decryptedKey []byte

	scanner := bufio.NewScanner(os.Stdin)
	for {
		// fmt.Printf("[%s]: ", senderId)
		scanner.Scan()
		userInput = scanner.Text()
		if userInput == "quit" {
			return
		}

		//user wants to share public key
		if userInput == "spk" {
			privateKey, publicKey := generateRSAKeyPair()
			pkmsg := Message {
				SenderId:	senderId,
				Timestamp: time.Now(),
				Message:  publicKey,
				MessageType: "PublicKey",
			}
			pkjsonData, err := json.Marshal(pkmsg)
			if err != nil {
				fmt.Println("Unable to marshall json:", err)
			}
			resp, err := http.Post("http://localhost:" + receiverPort, "application/json", bytes.NewBuffer(pkjsonData))
			if err != nil {
				fmt.Println("Unable to send public Key:", err)
				continue
			}

			if (resp.StatusCode != http.StatusOK) {
				fmt.Printf("SPK failed with: %d", resp.StatusCode)
				continue
			}
			var eskresp HTTPResponse
			respBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Failed to read response body:", err)
			}
			err = json.Unmarshal(respBody, &eskresp)
			if err != nil {
				fmt.Println("Failed to deserialize message:", err)
				return
			}
			decryptedKey = decryptSharedKey(eskresp.Response, privateKey)
			decryptionContext.mu.Lock()
			decryptionContext.decryptionKey = decryptedKey
			decryptionContext.mu.Unlock()

			fmt.Println("Key exchange was successful! Code: ", http.StatusOK)
		} else {
			decryptionContext.mu.Lock()
			if len(decryptionContext.decryptionKey) == 0 {
				fmt.Println("Please exchange keys first using command : spk")
				decryptionContext.mu.Unlock()
				continue
			}
			encryptedMessage, err := encryptMessage([]byte(userInput), decryptionContext.decryptionKey)

			decryptionContext.mu.Unlock()
			emsg := Message {
				SenderId:	senderId,
				Timestamp: time.Now(),
				Message:  encryptedMessage,
				MessageType: "EncryptedMessage",
			}
			emsgjson, err := json.Marshal(emsg)
			if err != nil {
				fmt.Println("Unable to marshal json:", err)
			}
			_, err = http.Post("http://localhost:" + receiverPort, "application/json", bytes.NewBuffer(emsgjson))
			if err != nil {
				fmt.Println("Unable to send Message:", err)
			}
		}
	}
}

func listenAndServe(listenerPort string, receiverPort string, decryptionContext *DecryptionContext, senderId string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read the received message from the request body
		jsonData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Println("Failed to read message:", err)
			return
		}

		// Deserialize the JSON-encoded message
		var receivedMsg Message
		err = json.Unmarshal(jsonData, &receivedMsg)
		if err != nil {
			fmt.Println("Failed to deserialize message:", err)
			return
		}

		//If user is receiving a public key from other peer we generate an encrypted shared key
		if receivedMsg.MessageType == "PublicKey" {
			encryptedSharedKey, plainTextSharedKey := generateAndEncryptSharedKey(receivedMsg.Message)
			resp := HTTPResponse{
				ResponseType:  "Encrypted Shared Key",
				Response:  encryptedSharedKey,
			}
			jsonData, err := json.Marshal(resp)
			if err != nil {
				fmt.Println("Failed to marshal json:", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Println("Key exchange was successful! Code: ", http.StatusOK)
			_, err2 := w.Write(jsonData)
    		if err != nil {
				fmt.Println("Failed to respond:", err2)
    		}

			decryptionContext.mu.Lock()
			decryptionContext.decryptionKey = plainTextSharedKey
			decryptionContext.mu.Unlock()

		
		} else if receivedMsg.MessageType == "EncryptedMessage" {
			decryptionContext.mu.Lock()
			if len(decryptionContext.decryptionKey) == 0 {
				fmt.Println("Please exchange keys first using command : spk")
				decryptionContext.mu.Unlock()
				return
			}
			decryptedMessage, err := decryptMessage(receivedMsg.Message, decryptionContext.decryptionKey)

			decryptionContext.mu.Unlock()

			if err != nil {
				fmt.Println("Failed to decrypt received message:", err)
				return
			}

			fmt.Printf("[%s]: %s\n", senderId, string(decryptedMessage))
		}
	})
	log.Fatal(http.ListenAndServe("localhost:" + listenerPort, nil))
}

