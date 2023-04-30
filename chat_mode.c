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
#include <poll.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "stnc.h"

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

	struct pollfd pfds[2];

	pfds[0].fd = STDIN_FILENO;
	pfds[0].events = POLLIN;

	pfds[1].fd = sockfd;
	pfds[1].events = POLLIN;

	while (1)
	{
		int num_events = poll(pfds, 2, -1);

		if (num_events < 0)
		{
			perror("poll");
			return EXIT_FAILURE;
		}

		else
		{
			if (pfds[0].revents & POLLIN)
			{
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
					fprintf(stdout, "Connection closed by the peer.\n");
					break;
				}

				memset(buffer, 0, MAX_MESSAGE_SIZE);
			}

			if (pfds[1].revents & POLLIN)
			{
				readBytes = recv(sockfd, buffer, MAX_MESSAGE_SIZE, 0);

				if (readBytes < 0)
				{
					perror("recv");
					return EXIT_FAILURE;
				}

				else if (readBytes == 0)
				{
					fprintf(stdout, "Connection closed by the peer.\n");
					break;
				}

				fprintf(stdout, "\nPeer: %s\n", buffer);

				memset(buffer, 0, MAX_MESSAGE_SIZE);
			}
		}
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

	int sockfd = INVALID_SOCKET, clientfd = INVALID_SOCKET, reuse = 1;

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


	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		perror("setsockopt");
		return EXIT_FAILURE;
	}

	memset(&server, 0, sizeof(server));
	memset(&client, 0, sizeof(client));

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
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

	fprintf(stdout, "Waiting for incoming connection...\n");

	clientfd = accept(sockfd, (struct sockaddr *)&client, (socklen_t *)&clientLen);

	if (clientfd < 0)
	{
		perror("accept");
		return EXIT_FAILURE;
	}

	// Close the listening socket, as we don't need it anymore (we now act as a client).
	close(sockfd);

	fprintf(stdout, "Connection established with %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

	struct pollfd pfds[2];

	pfds[0].fd = STDIN_FILENO;
	pfds[0].events = POLLIN;

	pfds[1].fd = clientfd;
	pfds[1].events = POLLIN;

	while (1)
	{
		int num_events = poll(pfds, 2, -1);

		if (num_events < 0)
		{
			perror("poll");
			close(clientfd);
			return EXIT_FAILURE;
		}

		else
		{
			if (pfds[1].revents & POLLIN)
			{
				readBytes = recv(clientfd, buffer, MAX_MESSAGE_SIZE, 0);

				if (readBytes < 0)
				{
					perror("recv");
					return EXIT_FAILURE;
				}

				else if (readBytes == 0)
				{
					fprintf(stdout, "Connection closed by the peer.\n");
					break;
				}

				fprintf(stdout, "\nPeer: %s\n", buffer);

				memset(buffer, 0, MAX_MESSAGE_SIZE);
			}

			if (pfds[0].revents & POLLIN)
			{
				fgets(buffer, MAX_MESSAGE_SIZE, stdin);

				buffer[strlen(buffer) - 1] = '\0';

				writeBytes = send(clientfd, buffer, strlen(buffer), 0);

				if (writeBytes < 0)
				{
					perror("send");
					return EXIT_FAILURE;
				}

				else if (writeBytes == 0)
				{
					fprintf(stdout, "Connection closed by the peer.\n");
					break;
				}

				memset(buffer, 0, MAX_MESSAGE_SIZE);
			}
		}
	}

	close(clientfd);

	return EXIT_SUCCESS;
}