package main

import (
	"fmt"
	"log"
)

func main() {

	var senderId string 
	var receiverId string 

	//Get sender's ID
	fmt.Printf("Enter sender ID: ")
	fmt.Scan(&senderId)

	//Get receiver's ID
	fmt.Printf("Enter receiver's ID: ")
	fmt.Scan(&receiverId)

	privateKey, publicKeyBytes := generateRSAKeyPair()
	encryptedSharedKey := generateAndEncryptSharedKey(publicKeyBytes)
	sharedKey := decryptSharedKey(encryptedSharedKey, privateKey)

	SharedKeyString := string(sharedKey)
	fmt.Println(SharedKeyString)

	sampleMesage := "Hi, There!"
	sampleMessageByteSequence := []byte(sampleMesage)
	
	//encrypt original message with shared key
	encryptedMessage, err := encryptMessage(sampleMessageByteSequence, sharedKey)
	if err != nil{
		log.Fatal(err)
	}

	//decrypt original message with shared key
	decryptedMessage, err := decryptMessage(encryptedMessage, sharedKey)
	if err != nil{
		log.Fatal(err)
	}

	decryptedMessageString := string(decryptedMessage)
	fmt.Println(sampleMesage)
	fmt.Println(decryptedMessageString)

}
