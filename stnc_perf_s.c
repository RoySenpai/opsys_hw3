/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Performance Mode - Server
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
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "stnc.h"

int32_t stnc_server_performance(char *port, bool quietMode) {
	struct sockaddr_in serverAddress, clientAddress;
	struct timeval start, end;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	char fileName[STNC_PROTO_MAX_SIZE] = { 0 };

	char *md5Hash = NULL;

	uint8_t *data_to_receive = NULL;

	stnc_packet *packetData = (stnc_packet *)buffer;

	socklen_t clientAddressLength = sizeof(clientAddress);
	uint16_t portNumber = atoi(port);

	stnc_transfer_protocol protocol = PROTOCOL_NONE;
	stnc_transfer_param param = PARAM_NONE;
	uint32_t fileSize = 0;

	double transferTime = 0.0;
	
	int32_t actual_received = 0, chatSocket = INVALID_SOCKET, serverSocket = INVALID_SOCKET, reuse = 1;

	memset(&serverAddress, 0, sizeof(serverAddress));
	memset(&clientAddress, 0, sizeof(clientAddress));

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(portNumber);
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

	if (portNumber < MIN_PORT_NUMBER)
	{
		fprintf(stderr, "Invalid port number.\n");
		return EXIT_FAILURE;
	}

	if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		perror("socket");
		return EXIT_FAILURE;
	}

	if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		perror("setsockopt");
		return EXIT_FAILURE;
	}
	
	if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		perror("bind");
		return EXIT_FAILURE;
	}

	if (listen(serverSocket, 1) < 0)
	{
		perror("listen");
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "Waiting for connection...\n");

	if ((chatSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength)) < 0)
	{
		perror("accept");
		return EXIT_FAILURE;
	}

	if (!quietMode)
	{
		fprintf(stdout, "Connection established with %s:%d\n", inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));
		fprintf(stdout, "Waiting for initilization packet...\n");
	}

	if (stnc_receive_tcp_data(chatSocket, buffer, quietMode) == -1 || stnc_get_packet_type(buffer) != MSGT_INIT)
	{
		fprintf(stderr, "Failed to receive initilization packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	protocol = stnc_get_packet_protocol(buffer);
	param = stnc_get_packet_param(buffer);
	fileSize = stnc_get_packet_size(buffer);

	if (!quietMode)
	{
		fprintf(stdout, "Initilization packet received.\n"
						"Protocol: %u\n"
						"Param: %u\n"
						"File size: %u\n", protocol, param, fileSize);

		fprintf(stdout, "Allocating %u bytes (%u KB) of memory...\n", fileSize, (fileSize / 1024));
	}

	data_to_receive = (uint8_t *)malloc(fileSize * sizeof(uint8_t));

	if (data_to_receive == NULL)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to allocate memory.\n");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_ALLOC, (strlen(err) + 1), (uint8_t *)err);
		stnc_send_tcp_data(chatSocket, buffer, quietMode);
		
		close(chatSocket);
		return EXIT_FAILURE;
	}

	stnc_prepare_packet(buffer, MSGT_ACK, protocol, param, ERRC_SUCCESS, 0, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending ACK packet...\n");

	if (stnc_send_tcp_data(chatSocket, buffer, quietMode) == -1)
	{
		fprintf(stderr, "Failed to send ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet sent.\n"
						"Waiting for data packet (file name)...\n");

	if (stnc_receive_tcp_data(chatSocket, buffer, quietMode) == -1 || stnc_get_packet_type(buffer) != MSGT_DATA)
	{
		fprintf(stderr, "Failed to receive data packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
	{
		fprintf(stdout, "Data packet received.\n");
		stnc_print_packet_data(packetData);
	}

	strcpy(fileName, ((char *)packetData + sizeof(stnc_packet)));

	fprintf(stdout, "Starting file transfer...\n");

	gettimeofday(&start, NULL);

	switch(protocol)
	{
		case PROTOCOL_IPV4:
		{
			actual_received = stnc_perf_server_ipv4(chatSocket, data_to_receive, fileSize, (portNumber + 1), param, quietMode);
			break;
		}

		case PROTOCOL_IPV6:
		{
			actual_received = stnc_perf_server_ipv6(chatSocket, data_to_receive, fileSize, (portNumber + 1), param, quietMode);
			break;
		}

		default:
		{
			fprintf(stderr, "Invalid protocol.\n");
			free(data_to_receive);
			close(chatSocket);
			return EXIT_FAILURE;
		}
	}

	if (actual_received == -1)
	{
		fprintf(stderr, "Failed to receive data packet.\n");
		free(data_to_receive);
		close(chatSocket);
		return EXIT_FAILURE;
	}

	gettimeofday(&end, NULL);

	fprintf(stdout, "File transfer complete.\n");

	md5Hash = util_md5_checksum(data_to_receive, actual_received);

	if (md5Hash == NULL)
	{
		fprintf(stderr, "Failed to calculate MD5 checksum.\n");
		free(data_to_receive);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "MD5 checksum of received data: %s\n", md5Hash);

	free(md5Hash);

	// Calculate transfer time here and whatever...

	transferTime = (double)(end.tv_sec - start.tv_sec) + ((double)(end.tv_usec - start.tv_usec) / 1000000);

	fprintf(stdout, "Total data received: %u KB (%0.2f%%).\n", (actual_received / 1024), (((float)actual_received / (float)fileSize) * 100));
	fprintf(stdout, "Transfer time: %lf seconds\n", transferTime);
	fprintf(stdout, "Transfer rate: %lf KB/s\n", ((double)actual_received / 1024) / transferTime);

	char statics[] = "Future statistics here.";

	stnc_prepare_packet(buffer, MSGT_DATA, protocol, param, ERRC_SUCCESS, (strlen(statics) + 1), (uint8_t *)statics);

	if (!quietMode)
		fprintf(stdout, "Sending statistics packet...\n");

	if (stnc_send_tcp_data(chatSocket, buffer, quietMode) == -1)
	{
		fprintf(stderr, "Failed to send statistics packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "Statistics packet sent.\n"
						"Waiting for end packet...\n");

	if (stnc_receive_tcp_data(chatSocket, buffer, quietMode) == -1 || stnc_get_packet_type(buffer) != MSGT_END)
	{
		fprintf(stderr, "Failed to receive end packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
	{
		fprintf(stdout, "End packet received.\n");
		stnc_print_packet_data(packetData);
		fprintf(stdout, "Closing connection and cleaning up memory...\n");
	}

	close(chatSocket);
	close(serverSocket);

	free(data_to_receive);

	if (!quietMode)
		fprintf(stdout, "Memory cleanup complete.\n"
						"Connection closed.\n"
						"Exiting...\n");


	return EXIT_SUCCESS;
}

int32_t stnc_perf_server_ipv4(int32_t chatsocket, uint8_t* data, uint32_t filesize, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	struct sockaddr_in serverAddress, clientAddress;
	socklen_t len = sizeof(clientAddress);

	uint32_t bytesReceived = 0;

	int32_t serverSocket = INVALID_SOCKET, reuse = 1;

	if ((serverSocket = socket(AF_INET, (param == PARAM_TCP ? SOCK_STREAM:SOCK_DGRAM), 0)) < 0)
	{
		if (!quietMode)
			perror("socket");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		if (!quietMode)
			perror("setsockopt");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);
		
		return -1;
	}

	memset(&serverAddress, 0, sizeof(serverAddress));
	memset(&clientAddress, 0, sizeof(clientAddress));

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddress.sin_port = htons(server_port);

	if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		if (!quietMode)
			perror("bind");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		close(serverSocket);
		return -1;
	}

	if (!quietMode)
		fprintf(stdout, "Binding completed.\n");

	if (param == PARAM_TCP)
	{
		if (listen(serverSocket, 1) < 0)
		{
			if (!quietMode)
				perror("listen");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		if (!quietMode)
		{
			fprintf(stdout, "Listening on port %u...\n"
							"Sending ACK to client to connect...\n",
							server_port);
		}

		stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_IPV4, param, ERRC_SUCCESS, 0, NULL);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		if (!quietMode)
			fprintf(stdout, "ACK sent, waiting for client to connect...\n");

		int32_t clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &len);

		if (clientSocket < 0)
		{
			if (!quietMode)
				perror("accept");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		if (!quietMode)
			fprintf(stdout, "Client connected from %s:%d\n", inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));

		close(serverSocket);

		struct pollfd fds[2];

		fds[0].fd = chatsocket;
		fds[0].events = POLLIN;

		fds[1].fd = clientSocket;
		fds[1].events = POLLIN;

		while (bytesReceived < filesize)
		{
			int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

			if (ret < 0)
			{
				if (!quietMode)
					perror("poll");

				char *err = strerror(errno);

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(clientSocket);

				return -1;
			}

			// This should never happen, and if it does, it's a critical bug.
			// Nevertherless, we still check for it.
			else if (ret == 0)
			{
				if (!quietMode)
					fprintf(stderr, "Poll timeout occured. Abort action immediately.\n");

				char err[] = "Poll timeout occured. Abort action immediately.";

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);

				return -1;
			}

			if (fds[0].revents & POLLIN)
			{
				if (!quietMode)
					fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");

				stnc_receive_tcp_data(chatsocket, buffer, quietMode);
				
				if (stnc_get_packet_error(buffer) != ERRC_SUCCESS)
				{
					if (!quietMode)
						fprintf(stderr, "Error occured while receiving data. Abort action immediately.\n");
					
					close(clientSocket);

					return -1;
				}

				break;
			}

			else if (fds[1].revents & POLLIN)
			{
				uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived));

				int32_t bytes = 0;

				bytes = recv(clientSocket, data + bytesReceived, bytesToReceive, 0);

				if (bytes <= 0)
				{
					if (!quietMode)
						perror("recv");

					char *err = strerror(errno);

					stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_RECV, (strlen(err) + 1), (uint8_t *) err);
					stnc_send_tcp_data(chatsocket, buffer, quietMode);

					close(clientSocket);
					return -1;
				}

				bytesReceived += (uint32_t)bytes;
			}
		}

		close(clientSocket);
	}

	else
	{
		struct pollfd fds[2];

		fds[0].fd = chatsocket;
		fds[0].events = POLLIN;

		fds[1].fd = serverSocket;
		fds[1].events = POLLIN;

		if (!quietMode)
			fprintf(stdout, "Sending ACK to client to start sending data...\n");

		stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_IPV4, param, ERRC_SUCCESS, 0, NULL);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		if (!quietMode)
			fprintf(stdout, "ACK sent, waiting for client to start sending data on port %u...\n", server_port);

		while (bytesReceived < filesize)
		{
			int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

			if (ret < 0)
			{
				if (!quietMode)
					perror("poll");

				char *err = strerror(errno);

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);

				return -1;
			}

			// This should never happen, and if it does, it's a critical bug.
			// Nevertherless, we still check for it.
			else if (ret == 0)
			{
				if (!quietMode)
					fprintf(stderr, "Poll timeout occured. Abort action immediately.\n");

				char err[] = "Poll timeout occured. Abort action immediately.";

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);

				return -1;
			}

			else if (ret > 0) 
			{
				if (fds[0].revents & POLLIN)
				{
					if (!quietMode)
						fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");

					stnc_receive_tcp_data(chatsocket, buffer, quietMode);
					stnc_print_packet_data((stnc_packet *)buffer);

					break;
				}

				if (fds[1].revents & POLLIN)
				{
					uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE_UDP) ? CHUNK_SIZE_UDP:(filesize - bytesReceived));

					int32_t bytes = 0;

					bytes = recvfrom(serverSocket, data + bytesReceived, bytesToReceive, 0, (struct sockaddr *)&clientAddress, &len);

					if (bytes <= 0)
					{
						if (!quietMode)
							perror("recvfrom");

						char *err = strerror(errno);

						stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_RECV, (strlen(err) + 1), (uint8_t *) err);
						stnc_send_tcp_data(chatsocket, buffer, quietMode);

						close(serverSocket);
						return -1;
					}

					bytesReceived += (uint32_t)bytes;
				}
			}
		}

		close(serverSocket);
	}

	if (!quietMode)
		fprintf(stdout, "Received %u bytes, expected %u bytes.\n", bytesReceived, filesize);

	return bytesReceived;
}

int32_t stnc_perf_server_ipv6(int32_t chatsocket, uint8_t* data, uint32_t filesize, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	struct sockaddr_in6 serverAddress, clientAddress;
	socklen_t len = sizeof(clientAddress);

	uint32_t bytesReceived = 0;

	int32_t serverSocket = INVALID_SOCKET, reuse = 1;

	if ((serverSocket = socket(AF_INET6, (param == PARAM_TCP ? SOCK_STREAM:SOCK_DGRAM), 0)) < 0)
	{
		if (!quietMode)
			perror("socket");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return EXIT_FAILURE;
	}

	if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		if (!quietMode)
			perror("setsockopt");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);
		
		return -1;
	}

	memset(&serverAddress, 0, sizeof(serverAddress));
	memset(&clientAddress, 0, sizeof(clientAddress));

	serverAddress.sin6_family = AF_INET6;
	serverAddress.sin6_port = htons(server_port);
	serverAddress.sin6_addr = in6addr_any;

	if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		if (!quietMode)
			perror("bind");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		close(serverSocket);
		return -1;
	}

	if (!quietMode)
		fprintf(stdout, "Binding completed.\n");

	if (param == PARAM_TCP)
	{
		if (listen(serverSocket, 1) < 0)
		{
			if (!quietMode)
				perror("listen");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		if (!quietMode)
		{
			fprintf(stdout, "Listening on port %u...\n"
							"Sending ACK to client to connect...\n",
							server_port);
		}

		stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_IPV4, param, ERRC_SUCCESS, 0, NULL);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		if (!quietMode)
			fprintf(stdout, "ACK sent, waiting for client to connect...\n");

		int32_t clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &len);

		if (clientSocket < 0)
		{
			if (!quietMode)
				perror("accept");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		if (!quietMode)
		{
			char clientIP[INET6_ADDRSTRLEN];

			if (inet_ntop(AF_INET6, &clientAddress.sin6_addr, clientIP, sizeof(clientIP)) == NULL)
			{
				if (!quietMode)
					perror("inet_ntop");

				char *err = strerror(errno);

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);
				return -1;
			}

			fprintf(stdout, "Client connected from %s:%d\n", clientIP, ntohs(clientAddress.sin6_port));
		}

		close(serverSocket);

		struct pollfd fds[2];

		fds[0].fd = chatsocket;
		fds[0].events = POLLIN;

		fds[1].fd = clientSocket;
		fds[1].events = POLLIN;

		while (bytesReceived < filesize)
		{
			int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

			if (ret < 0)
			{
				if (!quietMode)
					perror("poll");

				char *err = strerror(errno);

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(clientSocket);

				return -1;
			}

			// This should never happen, and if it does, it's a critical bug.
			// Nevertherless, we still check for it.
			else if (ret == 0)
			{
				if (!quietMode)
					fprintf(stderr, "Poll timeout occured. Abort action immediately.\n");

				char err[] = "Poll timeout occured. Abort action immediately.";

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);

				return -1;
			}

			if (fds[0].revents & POLLIN)
			{
				if (!quietMode)
					fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");

				stnc_receive_tcp_data(chatsocket, buffer, quietMode);
				
				if (stnc_get_packet_error(buffer) != ERRC_SUCCESS)
				{
					if (!quietMode)
						fprintf(stderr, "Error occured while receiving data. Abort action immediately.\n");
					
					close(clientSocket);

					return -1;
				}

				break;
			}

			else if (fds[1].revents & POLLIN)
			{
				uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived));

				int32_t bytes = 0;

				bytes = recv(clientSocket, data + bytesReceived, bytesToReceive, 0);

				if (bytes <= 0)
				{
					if (!quietMode)
						perror("recv");

					char *err = strerror(errno);

					stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_RECV, (strlen(err) + 1), (uint8_t *) err);
					stnc_send_tcp_data(chatsocket, buffer, quietMode);

					close(clientSocket);
					return -1;
				}

				bytesReceived += (uint32_t)bytes;
			}
		}

		close(clientSocket);
	}

	else
	{
		struct pollfd fds[2];

		fds[0].fd = chatsocket;
		fds[0].events = POLLIN;

		fds[1].fd = serverSocket;
		fds[1].events = POLLIN;

		if (!quietMode)
			fprintf(stdout, "Sending ACK to client to start sending data...\n");

		stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_IPV4, param, ERRC_SUCCESS, 0, NULL);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		if (!quietMode)
			fprintf(stdout, "ACK sent, waiting for client to start sending data on port %u...\n", server_port);

		while (bytesReceived < filesize)
		{
			int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

			if (ret < 0)
			{
				if (!quietMode)
					perror("poll");

				char *err = strerror(errno);

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);

				return -1;
			}

			// This should never happen, and if it does, it's a critical bug.
			// Nevertherless, we still check for it.
			else if (ret == 0)
			{
				if (!quietMode)
					fprintf(stderr, "Poll timeout occured. Abort action immediately.\n");

				char err[] = "Poll timeout occured. Abort action immediately.";

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);

				return -1;
			}

			else if (ret > 0) 
			{
				if (fds[0].revents & POLLIN)
				{
					if (!quietMode)
						fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");

					stnc_receive_tcp_data(chatsocket, buffer, quietMode);
					stnc_print_packet_data((stnc_packet *)buffer);

					break;
				}

				if (fds[1].revents & POLLIN)
				{
					uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE_UDP) ? CHUNK_SIZE_UDP:(filesize - bytesReceived));

					int32_t bytes = 0;

					bytes = recvfrom(serverSocket, data + bytesReceived, bytesToReceive, 0, (struct sockaddr *)&clientAddress, &len);

					if (bytes <= 0)
					{
						if (!quietMode)
							perror("recvfrom");

						char *err = strerror(errno);

						stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_RECV, (strlen(err) + 1), (uint8_t *) err);
						stnc_send_tcp_data(chatsocket, buffer, quietMode);

						close(serverSocket);
						return -1;
					}

					bytesReceived += (uint32_t)bytes;
				}
			}
		}

		close(serverSocket);
	}

	if (!quietMode)
		fprintf(stdout, "Received %u bytes, expected %u bytes.\n", bytesReceived, filesize);

	return bytesReceived;
}

int32_t stnc_perf_server_unix(int32_t chatsocket, uint8_t* data, uint32_t filesize, char *server_uds_path, stnc_transfer_param param, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	struct sockaddr_un serverAddress, clientAddress = {
        .sun_family = AF_UNIX,
    };

	uint32_t bytesReceived = 0;

	socklen_t clientAddressLength = sizeof(clientAddress);

	int32_t serverSocket = INVALID_SOCKET;

	int32_t len = sizeof(struct sockaddr_un) + strlen(server_uds_path);

	strcpy(serverAddress.sun_path, server_uds_path);
	unlink(server_uds_path);

	if ((serverSocket = socket(AF_UNIX, (param == PARAM_STREAM ? SOCK_STREAM : SOCK_DGRAM), 0)) < 0)
	{
		if (!quietMode)
			perror("socket");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if (bind(serverSocket, (struct sockaddr *)&serverAddress, len) < 0)
	{
		if (!quietMode)
			perror("bind");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		close(serverSocket);
		return -1;
	}

	if (param == PARAM_STREAM)
	{
		if (listen(serverSocket, 1) < 0)
		{
			if (!quietMode)
				perror("listen");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		int32_t clientSocket = INVALID_SOCKET;

		if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength)) < 0)
		{
			if (!quietMode)
				perror("accept");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		if (!quietMode)
			fprintf(stdout, "Client connected from \"%s\".\n", clientAddress.sun_path);

		close(serverSocket);

		while (bytesReceived < filesize)
		{
			uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived));

			int32_t bytes = 0;

			if (!quietMode)
				fprintf(stdout, "Receiving data packet (%u/%u)...\n", bytesReceived, filesize);

			bytes = recv(clientSocket, data + bytesReceived, bytesToReceive, 0);

			if (bytes == -1)
			{
				if (!quietMode)
					perror("recv");

				char *err = strerror(errno);

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_RECV, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(clientSocket);
				return -1;
			}

			bytesReceived += (uint32_t)bytes;
		}

		close(clientSocket);
	}

	else
	{
		while (bytesReceived < filesize)
		{
			uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived));

			int32_t bytes = 0;

			if (!quietMode)
				fprintf(stdout, "Receiving data packet (%u/%u)...\n", bytesReceived, filesize);

			bytes = recvfrom(serverSocket, data + bytesReceived, bytesToReceive, 0, (struct sockaddr *)&clientAddress, &clientAddressLength);

			if (bytes == -1)
			{
				if (!quietMode)
					perror("recvfrom");

				char *err = strerror(errno);

				stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_RECV, (strlen(err) + 1), (uint8_t *) err);
				stnc_send_tcp_data(chatsocket, buffer, quietMode);

				close(serverSocket);
				return -1;
			}

			bytesReceived += (uint32_t)bytes;
		}

		close(serverSocket);
	}

	if (!quietMode)
		fprintf(stdout, "Received %u bytes (%u MB).\n", bytesReceived, (bytesReceived / 1024) / 1024);

	return bytesReceived;
}

int32_t stnc_perf_server_memory(int32_t chatsocket, uint8_t* data, uint32_t filesize, char *file_name, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	uint8_t *dataToReceive = MAP_FAILED;

	int32_t fd = INVALID_SOCKET;

	if ((fd = open(file_name, O_RDONLY)) == -1)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to open file \"%s\"\n", file_name);

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if ((dataToReceive = mmap(NULL, sizeof(uint32_t) + filesize, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		if (!quietMode)
			perror("mmap");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		close(fd);
		return -1;
	}

	dataToReceive += sizeof(uint32_t);

	uint32_t bytesReceived = 0;

	while (bytesReceived < filesize)
	{
		uint32_t bytesToReceived = ((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived);

		memcpy(data + bytesReceived, dataToReceive, bytesToReceived);

		bytesReceived += bytesToReceived;
	}

	if (munmap(dataToReceive, sizeof(uint32_t) + filesize) == -1)
	{
		if (!quietMode)
			perror("munmap");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		close(fd);
		return -1;
	}

	close(fd);

	if (!quietMode)
		fprintf(stdout, "Received %u bytes (%u MB).\n", bytesReceived, (bytesReceived / 1024) / 1024);

	return bytesReceived;
}

int32_t stnc_perf_server_pipe(int32_t chatsocket, uint8_t* data, uint32_t filesize, char *file_name, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	int32_t fd = INVALID_SOCKET;

	if (mkfifo(file_name, 0666) == -1)
	{
		if (!quietMode)
			perror("mkfifo");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_PIPE, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if ((fd = open(file_name, O_RDONLY)) == -1)
	{
		if (!quietMode)
			perror("open");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_PIPE, PARAM_FILE, ERRC_PIPE, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	uint32_t bytesReceived = 0;

	while (bytesReceived < filesize)
	{
		uint32_t bytesToReceived = ((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived);

		if (read(fd, data + bytesReceived, bytesToReceived) == -1)
		{
			if (!quietMode)
				perror("write");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_PIPE, PARAM_FILE, ERRC_PIPE, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(fd);
			return -1;
		}

		bytesReceived += bytesToReceived;
	}

	close(fd);

	if (!quietMode)
		fprintf(stdout, "Received %u bytes (%u MB).\n", bytesReceived, (bytesReceived / 1024) / 1024);

	return bytesReceived;
}