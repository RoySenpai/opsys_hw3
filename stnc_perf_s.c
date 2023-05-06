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

#include "stnc.h"
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

struct timeval start, end;

int32_t stnc_server_performance(char *port, bool quietMode) {
	struct sockaddr_in serverAddress, clientAddress;

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
		fprintf(stdout, "Waiting for connections...\n");

	while (true)
	{
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
			fprintf(stdout, "Initilization packet received.\n");
			stnc_print_packet_data((stnc_packet *)buffer);
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

		if (!quietMode)
			fprintf(stdout, "Memory allocated.\n");

		if (protocol == PROTOCOL_MMAP || protocol == PROTOCOL_PIPE)
		{
			if (!quietMode)
				fprintf(stdout, "Sending ACK packet...\n");

			stnc_prepare_packet(buffer, MSGT_ACK, protocol, param, ERRC_SUCCESS, 0, NULL);
			stnc_send_tcp_data(chatSocket, buffer, quietMode);

			if (!quietMode)
				fprintf(stdout, "ACK packet sent.\n"
								"Waiting for data packet...\n");

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
		}

		if (!quietMode)
			fprintf(stdout, "Starting file transfer...\n");

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

			case PROTOCOL_UNIX:
			{
				actual_received = stnc_perf_server_unix(chatSocket, data_to_receive, fileSize, STNC_UNIX_NAME, param, quietMode);
				break;
			}

			case PROTOCOL_MMAP:
			{
				// ACK placeholder (we actually need to receive an ACK packet, but the client also expects an ACK packet)/
				stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_MMAP, PARAM_FILE, ERRC_SUCCESS, 0, NULL);
				stnc_send_tcp_data(chatSocket, buffer, quietMode);

				// Waiting for the client to actually start writing the file.
				stnc_receive_tcp_data(chatSocket, buffer, quietMode);

				actual_received = stnc_perf_server_memory(chatSocket, data_to_receive, fileSize, fileName, quietMode);
				break;
			}

			case PROTOCOL_PIPE:
			{
				actual_received = stnc_perf_server_pipe(chatSocket, data_to_receive, fileSize, fileName, quietMode);
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

		if (!quietMode)
			fprintf(stdout, "File transfer complete.\n");

		md5Hash = util_md5_checksum(data_to_receive, actual_received);

		if (md5Hash == NULL)
		{
			fprintf(stderr, "Failed to calculate MD5 checksum.\n");
			free(data_to_receive);
			return EXIT_FAILURE;
		}

		if (!quietMode)
			fprintf(stdout, "MD5 checksum of received data: %s\n", md5Hash);

		free(md5Hash);

		// Calculate transfer time here and whatever...

		transferTime = (double)(end.tv_sec - start.tv_sec) + ((double)(end.tv_usec - start.tv_usec) / 1000000);

		char statics[STNC_PROTO_MAX_SIZE] = { 0 };

		char *transferName = NULL;

		switch(protocol)
		{
			case PROTOCOL_IPV4:
			{
				if (param == PARAM_TCP)
					transferName = "IPv4 TCP:";

				else
					transferName = "IPv4 UDP:";

				break;
			}

			case PROTOCOL_IPV6:
			{
				if (param == PARAM_TCP)
					transferName = "IPv6 TCP:";

				else
					transferName = "IPv6 UDP:";

				break;
			}

			case PROTOCOL_UNIX:
			{
				if (param == PARAM_STREAM)
					transferName = "UDS Stream:";

				else
					transferName = "UDS Datagram:";

				break;
			}

			case PROTOCOL_MMAP:
			{
				transferName = "Memory Mapped File:";
				break;
			}

			case PROTOCOL_PIPE:
			{
				transferName = "Pipe:";
				break;
			}

			default:
			{
				transferName = "UNKNOWN";
				break;
			}
		}

		snprintf(statics, (sizeof(statics) - 1), "Total data received: %u KB (%0.2f%%)\nTransfer time: %0.3lf seconds (%0.3lf ms)\nTransfer rate: %0.3lf KB/s (%0.3lf MB/s)\n)", 
											(actual_received / 1024), (((float)actual_received / (float)fileSize) * 100), transferTime, (transferTime * 1000), (((double)actual_received / 1024) / transferTime), ((double)actual_received / (1024 * 1024)) / transferTime);

		if (!quietMode)
			fprintf(stdout, "%s\n%s", transferName, statics);
		
		else
			fprintf(stdout, "%s\n%s\n", transferName, statics);

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
			fprintf(stdout, "Closing connection and cleaning up memory...\n");
		}

		close(chatSocket);

		free(data_to_receive);

		if (!quietMode)
			fprintf(stdout, "Memory cleanup complete.\n"
							"Connection closed.\n"
							"Waiting for connections...\n");
	}

	close(serverSocket);

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

		gettimeofday(&start, NULL);

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

		gettimeofday(&start, NULL);

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
					stnc_receive_tcp_data(chatsocket, buffer, quietMode);

					if (!quietMode)
					{
						fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");
						stnc_print_packet_data((stnc_packet *)buffer);
					}

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

	gettimeofday(&end, NULL);

	if (bytesReceived == filesize)
	{
		// Syncronization with the sender.
		stnc_receive_tcp_data(chatsocket, buffer, quietMode);
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

		gettimeofday(&start, NULL);

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

		gettimeofday(&start, NULL);

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
					stnc_receive_tcp_data(chatsocket, buffer, quietMode);

					if (!quietMode)
					{
						fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");
						stnc_print_packet_data((stnc_packet *)buffer);
					}

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

	gettimeofday(&end, NULL);

	if (bytesReceived == filesize)
	{
		// Syncronization with the sender.
		stnc_receive_tcp_data(chatsocket, buffer, quietMode);
	}


	if (!quietMode)
		fprintf(stdout, "Received %u bytes, expected %u bytes.\n", bytesReceived, filesize);

	return bytesReceived;
}

int32_t stnc_perf_server_unix(int32_t chatsocket, uint8_t* data, uint32_t filesize, char *server_uds_path, stnc_transfer_param param, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	struct sockaddr_un serverAddress, clientAddress;

	uint32_t bytesReceived = 0;

	socklen_t clientAddressLength = sizeof(clientAddress);

	int serverSocket = INVALID_SOCKET;

	memset(&serverAddress, 0, sizeof(struct sockaddr_un));
	memset(&clientAddress, 0, sizeof(struct sockaddr_un));

	serverAddress.sun_family = AF_UNIX;

	strcpy(serverAddress.sun_path, server_uds_path);
	unlink(server_uds_path);

	int len = strlen(serverAddress.sun_path) + sizeof(serverAddress.sun_family);

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

	if (!quietMode)
		fprintf(stdout, "Binding completed.\n");

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

		if (!quietMode)
		{
			fprintf(stdout, "Listening on path %s...\n"
							"Sending ACK to client to connect...\n",
							server_uds_path);
		}

		stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_IPV4, param, ERRC_SUCCESS, 0, NULL);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		if (!quietMode)
			fprintf(stdout, "ACK sent, waiting for client to connect...\n");

		int32_t clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);

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
			fprintf(stdout, "Client connected");

		close(serverSocket);

		struct pollfd fds[2];

		fds[0].fd = chatsocket;
		fds[0].events = POLLIN;

		fds[1].fd = clientSocket;
		fds[1].events = POLLIN;

		gettimeofday(&start, NULL);

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
			fprintf(stdout, "ACK sent, waiting for client to start sending data on path %s...\n", server_uds_path);

		gettimeofday(&start, NULL);

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
					stnc_receive_tcp_data(chatsocket, buffer, quietMode);

					if (!quietMode)
					{
						fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");
						stnc_print_packet_data((stnc_packet *)buffer);
					}

					break;
				}

				if (fds[1].revents & POLLIN)
				{
					uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE_UDP) ? CHUNK_SIZE_UDP:(filesize - bytesReceived));

					int32_t bytes = 0;

					bytes = recvfrom(serverSocket, data + bytesReceived, bytesToReceive, 0, (struct sockaddr *)&clientAddress, &clientAddressLength);

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

	gettimeofday(&end, NULL);

	if (bytesReceived == filesize)
	{
		// Syncronization with the sender.
		stnc_receive_tcp_data(chatsocket, buffer, quietMode);
	}

	// Cleanup
	unlink(server_uds_path);

	if (!quietMode)
		fprintf(stdout, "Received %u bytes, expected %u bytes.\n", bytesReceived, filesize);

	return bytesReceived;
}

int32_t stnc_perf_server_memory(int32_t chatsocket, uint8_t* data, uint32_t filesize, char *file_name, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	uint8_t *dataToReceive = MAP_FAILED;

	int32_t fd = INVALID_SOCKET;

	FILE* fp = NULL;

	if ((fp = fopen(file_name, "r")) == NULL)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to open file \"%s\"\n", file_name);

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	fd = fileno(fp);

	if ((dataToReceive = mmap(NULL, sizeof(uint32_t) + filesize, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		if (!quietMode)
			perror("mmap");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		fclose(fp);
		return -1;
	}

	uint8_t *dataToReceive_tmp = dataToReceive + sizeof(uint32_t);

	uint32_t bytesReceived = 0;

	struct pollfd fds[2];

	fds[0].fd = chatsocket;
	fds[0].events = POLLIN;

	fds[1].fd = fd;
	fds[1].events = POLLIN;

	gettimeofday(&start, NULL);

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

			fclose(fp);

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

			fclose(fp);

			return -1;
		}

		if (fds[0].revents & POLLIN)
		{
			stnc_receive_tcp_data(chatsocket, buffer, quietMode);
			
			if (!quietMode)
			{
				fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");
				stnc_print_packet_data((stnc_packet *)buffer);
			}

			break;
		}

		if (fds[1].revents & POLLIN)
		{
			uint32_t bytesToReceived = ((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived);

			memcpy(data, dataToReceive, bytesToReceived);

			data += bytesToReceived;
			dataToReceive_tmp += bytesToReceived;

			bytesReceived += bytesToReceived;
		}
	}

	if (munmap(dataToReceive, sizeof(uint32_t) + filesize) == -1)
	{
		if (!quietMode)
			perror("munmap");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		fclose(fp);
		return -1;
	}

	gettimeofday(&end, NULL);

	fclose(fp);

	if (bytesReceived == filesize)
	{
		// Syncronization with the sender.
		stnc_receive_tcp_data(chatsocket, buffer, quietMode);
	}

	// Clean up, remove the file, as it's no longer needed.
	remove(file_name);

	if (!quietMode)
		fprintf(stdout, "Received %u bytes (%u MB).\n", bytesReceived, (bytesReceived / 1024) / 1024);

	return bytesReceived;
}

int32_t stnc_perf_server_pipe(int32_t chatsocket, uint8_t* data, uint32_t filesize, char *file_name, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	int32_t fd = INVALID_SOCKET;

	stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_PIPE, PARAM_FILE, ERRC_SUCCESS, 0, NULL);
	stnc_send_tcp_data(chatsocket, buffer, quietMode);

	if (mkfifo(file_name, 0644) == -1)
	{
		// Ignore the error if the file already exists, since it's OK.
		if (errno != EEXIST)
		{
			if (!quietMode)
				perror("mknod");
			
			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_PIPE, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			return -1;
		}
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

	struct pollfd fds[2];

	fds[0].fd = chatsocket;
	fds[0].events = POLLIN;

	fds[1].fd = fd;
	fds[1].events = POLLIN;

	gettimeofday(&start, NULL);

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

			close(fd);

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

			close(fd);

			return -1;
		}

		if (fds[0].revents & POLLIN)
		{
			stnc_receive_tcp_data(chatsocket, buffer, quietMode);
			
			if (!quietMode)
			{
				fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");
				stnc_print_packet_data((stnc_packet *)buffer);
			}

			break;
		}

		if (fds[1].revents & POLLIN)
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
	}

	gettimeofday(&end, NULL);

	close(fd);

	if (bytesReceived == filesize)
	{
		// Syncronization with the sender.
		stnc_receive_tcp_data(chatsocket, buffer, quietMode);
	}

	// Clean up, remove the file, as it's no longer needed.
	unlink(file_name);

	if (!quietMode)
		fprintf(stdout, "Received %u bytes (%u MB).\n", bytesReceived, (bytesReceived / 1024) / 1024);

	return bytesReceived;
}