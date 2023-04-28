/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) program
 *  Copyright (C) 2023  Roy Simanovich and Linor Ronen
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "stnc.h"

int main(int argc, char **argv) {
	printLicense();

	if (argc < 2)
	{
		printUsage(*argv);
		return EXIT_FAILURE;
	}

	else if (strcmp(*(argv + 1), "-c") == 0)
	{
		if (argc < 4 || argc > 7)
		{
			printClientUsage(*argv);
			return EXIT_FAILURE;
		}

		else if (argc == 4)
		{
			fprintf(stdout, "Client chat mode\n");
			return client_chat_mode(*(argv + 2), *(argv + 3));
		}

		else if (strcmp(*(argv + 4), "-p") == 0)
		{
			if (argc != 7)
			{
				printClientUsage(*argv);
				return EXIT_FAILURE;
			}

			fprintf(stdout, "Client performance mode\n");
			return client_performance_mode(*(argv + 2), *(argv + 3), *(argv + 5), *(argv + 6));
		}

		else
		{
			printClientUsage(*argv);
			return EXIT_FAILURE;
		}
	}

	else if (strcmp(*(argv + 1), "-s") == 0)
	{
		if (argc < 3 || argc > 5)
		{
			printServerUsage(*argv);
			return EXIT_FAILURE;
		}

		else if (argc == 3)
		{
			fprintf(stdout, "Server chat mode\n");
			return server_chat_mode(*(argv + 2));
		}

		else if (strcmp(*(argv + 3), "-p") == 0)
		{
			bool quietmode = false;

			if (argc != 4 && argc != 5)
			{
				printServerUsage(*argv);
				return EXIT_FAILURE;
			}

			else if (argc == 5)
			{
				if (strcmp(*(argv + 4), "-q") == 0)
					quietmode = true;

				else
				{
					printServerUsage(*argv);
					return EXIT_FAILURE;
				}
			}

			fprintf(stdout, "Server performance mode\n");
			return server_performance_mode(*(argv + 2), quietmode);
		}

		else
		{
			printServerUsage(*argv);
			return EXIT_FAILURE;
		}
	}

	else
	{
		printUsage(*argv);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void printUsage(char *programName) {
	fprintf(stdout, "Student Network Communication (STNC) usage:\n");
	fprintf(stdout, "Client mode: %s -c <ip> <port> [-p <type> <param>]\n", programName);
	fprintf(stdout, "Server mode: %s -s <port> [-p] [-q]\n", programName);
}

void printClientUsage(char *programName) {
	fprintf(stdout, "Usage: %s -c <ip> <port> [-p <type> <param>]\n", programName);
}

void printServerUsage(char *programName) {
	fprintf(stdout, "Usage: %s -s <port> [-p] [-q]\n", programName);
}

void printLicense() {
	fprintf(stdout, "Student Network Communication (STNC)  Copyright (C) 2023  Roy Simanovich and Linor Ronen\n"
					"This program comes with ABSOLUTELY NO WARRANTY.\n"
					"This is free software, and you are welcome to redistribute it\n"
					"under certain conditions; see `LICENSE' for details.\n\n");
}

int client_chat_mode(char *ip, char *port) {
	struct sockaddr_in server;
	char buffer[MAX_MESSAGE_SIZE] = {0};

	uint16_t portNumber = atoi(port);
	ssize_t writeBytes = 0, readBytes = 0;

	int sockfd = INVALID_SOCKET;

	if (portNumber < MIN_PORT_NUMBER)
	{
		fprintf(stderr, "Invalid port number: %s\n", port);
		return EXIT_FAILURE;
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		perror("socket");
		return EXIT_FAILURE;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(portNumber);

	if (inet_pton(AF_INET, ip, &server.sin_addr) <= 0)
	{
		perror("inet_pton");
		return EXIT_FAILURE;
	}

	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		perror("connect");
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Connection established to %s:%s\n", ip, port);

	while (1)
	{
		fprintf(stdout, "Enter message: ");
		fgets(buffer, MAX_MESSAGE_SIZE, stdin);

		buffer[strlen(buffer) - 1] = '\0';

		writeBytes = send(sockfd, buffer, strlen(buffer), 0);

		if (writeBytes < 0)
		{
			perror("send");
			return EXIT_FAILURE;
		}

		else if (writeBytes == 0)
		{
			fprintf(stdout, "Connection closed by the server.\n");
			break;
		}

		readBytes = recv(sockfd, buffer, MAX_MESSAGE_SIZE, 0);

		if (readBytes < 0)
		{
			perror("recv");
			return EXIT_FAILURE;
		}

		else if (readBytes == 0)
		{
			fprintf(stdout, "Connection closed by the server.\n");
			break;
		}

		fprintf(stdout, "Server response: %s\n", buffer);

		memset(buffer, 0, MAX_MESSAGE_SIZE);
	}

	close(sockfd);

	return EXIT_SUCCESS;
}

int server_chat_mode(char *port) {
	struct sockaddr_in server, client;

	char buffer[MAX_MESSAGE_SIZE] = {0};

	uint16_t portNumber = atoi(port);
	socklen_t clientLen = sizeof(client);
	ssize_t writeBytes = 0, readBytes = 0;

	int sockfd = INVALID_SOCKET, clientfd = INVALID_SOCKET;

	if (portNumber < MIN_PORT_NUMBER)
	{
		fprintf(stderr, "Invalid port number: %s\n", port);
		return EXIT_FAILURE;
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		perror("socket");
		return EXIT_FAILURE;
	}

	memset(&server, 0, sizeof(server));
	memset(&client, 0, sizeof(client));

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(portNumber);

	if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		perror("bind");
		return EXIT_FAILURE;
	}

	if (listen(sockfd, 1) < 0)
	{
		perror("listen");
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Waiting for incoming connections...\n");

	clientfd = accept(sockfd, (struct sockaddr *)&client, (socklen_t *)&clientLen);

	if (clientfd < 0)
	{
		perror("accept");
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Connection established with %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

	while (1)
	{
		readBytes = recv(clientfd, buffer, MAX_MESSAGE_SIZE, 0);

		if (readBytes < 0)
		{
			perror("recv");
			return EXIT_FAILURE;
		}

		else if (readBytes == 0)
		{
			fprintf(stdout, "Connection closed by the client.\n");
			break;
		}

		fprintf(stdout, "Client message: %s\n", buffer);

		writeBytes = send(clientfd, buffer, strlen(buffer), 0);

		if (writeBytes < 0)
		{
			perror("send");
			return EXIT_FAILURE;
		}

		else if (writeBytes == 0)
		{
			fprintf(stdout, "Connection closed by the client.\n");
			break;
		}

		memset(buffer, 0, MAX_MESSAGE_SIZE);
	}

	close(clientfd);
	close(sockfd);

	return EXIT_SUCCESS;
}

int client_performance_mode(char *ip, char *port, char *transferProtocol, char *transferParam) {
	transfer_protocol protocol = getTransferProtocol(transferProtocol);
	transfer_param param = getTransferParam(transferParam);

	if (protocol == PROTOCOL_NONE || (param == PARAM_NONE && protocol != PROTOCOL_MMAP && protocol != PROTOCOL_PIPE))
	{
		fprintf(stderr, "Invalid transfer protocol or transfer param.\n");
		return EXIT_FAILURE;
	}

	if (!isFileExists(FILE_NAME))
	{
		fprintf(stdout, "File \"%s\" not found. Generating random data...\n", FILE_NAME);
		FILE *fd = fopen(FILE_NAME, "w");
		generateRandomData(fd, FILE_SIZE);
		fclose(fd);
	}

	fprintf(stdout, "IP: %s; Port: %s; Transfer protocol: %s; Transfer param: %s\n", ip, port, transferProtocol, transferParam);
	fprintf(stdout, "Client performance mode not implemented yet.\n");
	fprintf(stdout, "Exiting...\n");

	return EXIT_SUCCESS;
}

int server_performance_mode(char *port, bool quietMode) {
	fprintf(stdout, "Port: %s; Quiet mode: %s\n", port, quietMode ? "true" : "false");
	fprintf(stdout, "Server performance mode not implemented yet.\n");
	fprintf(stdout, "Exiting...\n");
	return EXIT_SUCCESS;
}

int generateRandomData(FILE *fd, uint64_t size) {
	if (fd == NULL)
	{
		fprintf(stderr, "Invalid file descriptor.\n");
		return EXIT_FAILURE;
	}

	if (size == 0)
	{
		fprintf(stderr, "Invalid size.\n");
		return EXIT_FAILURE;
	}

	uint8_t buffer[CHUNK_SIZE] = { 0 };
	u_int64_t remainingBytes = size;

	fprintf(stdout, "Generating %lu bytes (%lu MB) of random data...\n", size, (size / 1024 / 1024));
	fprintf(stdout, "Chunk size: %d bytes (%d KB)\n", CHUNK_SIZE, (CHUNK_SIZE / 1024));

	while (remainingBytes > 0)
	{
		uint32_t bytesToWrite = (remainingBytes > CHUNK_SIZE) ? CHUNK_SIZE : remainingBytes;

		for (uint32_t i = 0; i < bytesToWrite; i++)
			buffer[i] = rand() % 256;

		if (fwrite(buffer, sizeof(char), bytesToWrite, fd) != bytesToWrite)
		{
			fprintf(stderr, "Failed to write to file.\n");
			return EXIT_FAILURE;
		}

		remainingBytes -= bytesToWrite;
	}

	fprintf(stdout, "Successfully generated %lu bytes (%lu MB) of random data.\n", size, (size / 1024 / 1024));

	return EXIT_SUCCESS;
}

bool isFileExists(char *filename) {
	FILE *fd = fopen(filename, "rb");

	if (fd == NULL)
		return 0;

	fclose(fd);

	return 1;
}

transfer_protocol getTransferProtocol(char *transferType) {
	if (strcmp(transferType, "ipv4") == 0)
		return PROTOCOL_IPV4;

	else if (strcmp(transferType, "ipv6") == 0)
		return PROTOCOL_IPV6;

	else if (strcmp(transferType, "uds") == 0)
		return PROTOCOL_UNIX;

	else if (strcmp(transferType, "mmap") == 0)
		return PROTOCOL_MMAP;

	else if (strcmp(transferType, "pipe") == 0)
		return PROTOCOL_PIPE;

	return PROTOCOL_NONE;
}

transfer_param getTransferParam(char *transferParam) {
	if (strcmp(transferParam, "tcp") == 0)
		return PARAM_TCP;

	else if (strcmp(transferParam, "udp") == 0)
		return PARAM_UDP;

	else if (strcmp(transferParam, "stream") == 0)
		return PARAM_STREAM;

	else if (strcmp(transferParam, "dgram") == 0)
		return PARAM_DGRAM;

	return PARAM_NONE;
}