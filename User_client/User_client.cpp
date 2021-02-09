// FMSH_Blockchain_base.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <process.h>
#include <thread>             // std::thread, std::this_thread::yield
#include <mutex>              // std::mutex, std::unique_lock
#include <condition_variable>
#include <iostream>
#include <string>
#include <chrono>
#include <ctime>
#include <fstream>
#include <vector>
#include <bitset>
#include "dsa.h"
#include "osrng.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "43012"

using namespace CryptoPP;
//using namespace std;

int timePerBlock = 3;

int mainComplexity;
int compPower;
bool isServerOnline = true;
bool hasReceivedBlock = false;
bool hasReceivedBlockchain = false;

std::mutex m;
std::condition_variable cv;
std::condition_variable cvComplexity;

//Send a new transaction to the server
void SendTransactionToServer(std::string transaction, SOCKET serverSocket) {
	int iSendResult;
	char const *sendbuf = transaction.c_str();

	//std::cout << "Sending out transaction data: " << sendbuf << std::endl;

	iSendResult = send(serverSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (iSendResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(serverSocket);
		//WSACleanup();
	}
	std::cout << "LOG: Sent out transaction data to the server: " << sendbuf << std::endl;
}

//Parser of incoming data
std::string HandleIncomingData(std::string data) {
	size_t end = data.find(';');
	if (end < 0) {
		printf("Received data in wrong format!\n");
		return "";
	}
	size_t start = data.find(':');
	if (start < 0) {
		printf("Received data in wrong format!\n");
		return "";
	}
	std::string type = data.substr(0, start);

	data = data.substr(start + 1, end - start - 1);
	if (type == "Confirmation") {
		if (data == "True") {
			std::cout << "LOG: Received confirmation for transaction sent;\n";
		}
		else {
			std::cout << "LOG: Sent transaction was rejected;\n";
		}
		return "";
	}
	else {
		printf("Received data in wrong format!\n");
		return "";
	}
}

//Session with the server
DWORD WINAPI SessionWithServer(LPVOID data) {

	SOCKET ConnectSocket = (SOCKET)data;
	// Process the client.

	int iSendResult;
	int iResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;
	std::string receivedData;

	std::string clientType = "Transactions;";
	char const *sendbuf = clientType.c_str();

	//std::cout << "Sending out client type data: " << sendbuf << std::endl;

	iSendResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (iSendResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		//WSACleanup();
	}
	
	std::cout << "LOG: Connected to the server\n";

	// Receiving all kinds of data
	do {
		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
			//printf("Bytes received: %d\n", iResult);
			receivedData = HandleIncomingData(std::string(recvbuf));
		}
		else if (iResult == 0)
			std::cout << "LOG: Connection closed with server on socket " + std::to_string(ConnectSocket) << std::endl;
		else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
		}

	} while (iResult > 0);

	// shutdown the connection since we're done
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		//WSACleanup();
	}

	// cleanup
	closesocket(ConnectSocket);
	//WSACleanup();

	std::cout << "LOG: Server disconnected, shutting down\n";
	isServerOnline = false;
	return 0;

}

//Not mine
SOCKET ConnectToServer(char* address) {
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return INVALID_SOCKET;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(address, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return INVALID_SOCKET;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return INVALID_SOCKET;
	}

	return ConnectSocket;

}

std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

std::string string_to_binary(std::string input) {
	std::string binaryString = "";
	for (char& _char : input) {
		binaryString += std::bitset<8>(_char).to_string();
	}
	return binaryString;
}

int main(int argc, char **argv)
{

	// Validate the parameters
	if (argc != 2) {
		printf("usage: %s server-address\n", argv[0]);
		return 1;
	}

	std::cout << "LOG: Connecting to server..." << std::endl;

	SOCKET ConnectSocket = ConnectToServer(argv[1]);

	if (ConnectSocket == INVALID_SOCKET) {
		std::cout << "LOG: Connection failed, restart the program while making sure server is running\n";
		return 1;
	}

	//std::cout << "Connection succeeded!\n";

	DWORD dwThreadId;

	CreateThread(NULL, 0, SessionWithServer, (LPVOID)ConnectSocket, 0, &dwThreadId);

	AutoSeededRandomPool rng;

	// Generate Private Key
	DSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(rng, 1024);

	// Generate Public Key   
	DSA::PublicKey publicKey;
	publicKey.AssignFrom(privateKey);
	if (!privateKey.Validate(rng, 3) || !publicKey.Validate(rng, 3))
	{
		throw std::runtime_error("DSA key generation failed");
	}

	std::string encodedPublicKey, encodedPrivateKey;

	// Serialize in PKCS#8 and X.509 format
	publicKey.Save(StringSink(encodedPublicKey).Ref());
	privateKey.Save(StringSink(encodedPrivateKey).Ref());

	std::cout << "LOG: Public key:\n" << string_to_hex(encodedPublicKey) << std::endl;
	std::cout << "LOG: Public key length:" << string_to_hex(encodedPublicKey).length() << std::endl;
	std::cout << "LOG: Private key:\n" << string_to_hex(encodedPrivateKey) << std::endl;
	std::cout << "LOG: Private key length:" << string_to_hex(encodedPrivateKey).length() << std::endl;

	// Decode DSA keys
	/*DSA::PrivateKey decodedPrivateKey;
	decodedPrivateKey.Load( StringStore(encodedPrivateKey).Ref() );

	DSA::PublicKey decodedPublicKey;
	decodedPublicKey.Load( StringStore(encodedPublicKey).Ref() );*/

	DSA::Signer signer(privateKey);
	DSA::Verifier verifier(publicKey);

	std::string input, signature;

	while (isServerOnline) {

		// Entering transactions until server is down

		std::cout << "Enter a transaction (string of data) to send\n";
		std::cin >> input;
		
		//StringSource ss1(input, true, new SignerFilter(rng, signer, new StringSink(signature)) ); // StringSource
		//StringSource ss2(input + signature, true, new SignatureVerificationFilter(verifier, NULL) );

		//std::cout << "Signature:\n" << string_to_hex(signature) << std::endl;

		//std::cout << "Verified signature on message" << std::endl; 
		//signature = "";

		SendTransactionToServer("Transaction:"+input+";", ConnectSocket);

		Sleep(100);

	}

	std::string s;
	std::cin >> s;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
