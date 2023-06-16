package main

import (
	"os"
	"sync"
)

func main() {

	senderId := os.Args[1]		//sender's Id
	senderPort := os.Args[2]	//sender's port to listen and serve
	receiverPort := os.Args[3]	//receiver's port to listen and serve

	decryptionContext := &DecryptionContext{}
	decryptionContext.cond = sync.NewCond(&decryptionContext.mu)

	var wg sync.WaitGroup
	wg.Add(1)

	//accept user input
	go acceptUserInput(&wg ,receiverPort, decryptionContext, senderId)

	//Start HTTP server and listen for messages
	go listenAndServe(senderPort, receiverPort, decryptionContext, senderId)

	wg.Wait()
}
