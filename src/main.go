package main

import (
	"fmt"
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

	myString := string(sharedKey)
	fmt.Printf(myString)

}
