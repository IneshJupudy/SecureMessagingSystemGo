# **SecureMessagingSystemGo**
A secure messaging system to send encrypted messages.               
<div align="center">
	<code><img width="50" src="https://user-images.githubusercontent.com/25181517/192107854-765620d7-f909-4953-a6da-36e1ef69eea6.png" alt="HTTP" title="HTTP"/></code>
	<code><img width="50" src="https://user-images.githubusercontent.com/25181517/192108374-8da61ba1-99ec-41d7-80b8-fb2f7c0a4948.png" alt="GitHub" title="GitHub"/></code>
	<code><img width="50" src="https://user-images.githubusercontent.com/25181517/192108891-d86b6220-e232-423a-bf5f-90903e6887c3.png" alt="Visual Studio Code" title="Visual Studio Code"/></code>
	<code><img width="50" src="https://user-images.githubusercontent.com/25181517/192149581-88194d20-1a37-4be8-8801-5dc0017ffbbe.png" alt="Go" title="Go"/></code>
</div>

## **How to Install and Run the Project** ##
1. Download the latest release as per your system
2. Open 2 terminals
3. Run `./sms {#Sender Id} {#Sender's port number} {#Receiver's port number}` on the first terminal
4. Run `./sms {#Sender Id} {#Sender's port number} {#Receiver's port number}` on the second terminal

**NOTE**: The sender's port number and receiver's port number in points 4 and 5 respectively should be the same. Similarly, the receiver's port number and sender's port number in points 4 and 5 respectively should be the same. 
  Eg: Terminal 1 - ./sms John 8080 8000
      Terminal 2 - ./sms Jane 8000 8080

5. Initiate the Key exchange with the command `spk` on one of the terminals.
6. Now you can start messaging on either terminal and see the message on the other peer's terminal.
7. To quit the program you can use the command "quit"

## **Design Decisions for the code** ##
I have broken the project into 3 primary tasks to maintain abstraction : 
  1. Key Exchange
  2. Encryption/Decryption of messages
  3. Sending messages over HTTP protocols

I have used several design principles here for a clean code :

  1. Single Responsibility Principle:- Each function written focuses on handling only one specific task.
  2. Separation of concerns:- Each part of the code handles different concerns of the overall project (eg: encryption, decryption, message handling, etc)
  3. Structs:- For a clean, organized, and readable data collection.
  4. Error Handling:- Correctly used log.Fatal instead of a simple print for callers to return from a failed error.
  5. Reusability:- The code is broken into segments that can be reused (eg: Encryption)
  6. Concurrency and synchronization:- To maintain availability and avoid breakdowns I have properly used Golang's features of thread safety by using condition variables(eg: To handle access to decryption key), goroutines, and mutexes.
  7. Comments:- There are ample comments to help a new contributor/reader properly understand and sync with the existing code.

