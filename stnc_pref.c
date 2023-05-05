/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Performance Mode
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "stnc.h"

int client_performance_mode(char *ip, char *port, char *transferProtocol, char *transferParam, bool quietMode) {
	struct sockaddr_in serverAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	uint8_t *data_to_send = NULL;

	int chatSocket = INVALID_SOCKET;
	uint16_t portNumber = atoi(port);

	stnc_transfer_protocol protocol = stnc_get_transfer_protocol(transferProtocol);
	stnc_transfer_param param = stnc_get_transfer_param(transferParam);

	if (portNumber < MIN_PORT_NUMBER)
	{
		fprintf(stderr, "Invalid port number.\n");
		return EXIT_FAILURE;
	}

	else if (protocol == PROTOCOL_NONE || (param == PARAM_NONE && protocol != PROTOCOL_MMAP && protocol != PROTOCOL_PIPE))
	{
		fprintf(stderr, "Invalid transfer protocol or transfer param.\n");
		return EXIT_FAILURE;
	}

	else if (((protocol == PROTOCOL_IPV4 || protocol == PROTOCOL_IPV6) && (param != PARAM_TCP && param != PARAM_UDP)) || (protocol == PROTOCOL_UNIX && (param != PARAM_STREAM && param != PARAM_DGRAM)))
	{
		fprintf(stderr, "Invalid transfer param.\n");
		return EXIT_FAILURE;
	}

	if (protocol == PROTOCOL_MMAP || protocol == PROTOCOL_PIPE)
		param = PARAM_FILE;

	data_to_send = generate_random_data(FILE_SIZE);

	if (data_to_send == NULL)
	{
		fprintf(stderr, "Failed to generate random data.\n");
		return EXIT_FAILURE;
	}

	char *md5 = md5_calculate_checksum(data_to_send, FILE_SIZE);

	if (md5 == NULL)
	{
		fprintf(stderr, "Failed to calculate MD5 checksum.\n");
		free(data_to_send);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "MD5 checksum: %s\n", md5);

	free(md5);

	memset(&serverAddress, 0, sizeof(serverAddress));

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(portNumber);

	if (inet_pton(AF_INET, ip, &serverAddress.sin_addr) <= 0)
	{
		perror("inet_pton");
		free(data_to_send);
		return EXIT_FAILURE;
	}

	if ((chatSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		perror("socket");
		free(data_to_send);
		return EXIT_FAILURE;
	}

	if (connect(chatSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		perror("connect");
		free(data_to_send);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Connected to server %s:%d.\n", ip, portNumber);

	stnc_prepare_packet(buffer, MSGT_INIT, protocol, param, ERRC_SUCCESS, FILE_SIZE, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending initilization packet (file size, protocol, param)...\n");

	if (stnc_send_tcp_data(chatSocket, buffer, false) == -1)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to send initilization packet.\n");
			
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "Initilization packet sent.\n"
						"Waiting for ACK packet...\n");

	if (stnc_receive_tcp_data(chatSocket, buffer, false) == -1 || stnc_get_packet_type(buffer) != MSGT_ACK)
	{
		fprintf(stderr, "Failed to receive ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet received.\n");

	stnc_prepare_packet(buffer, MSGT_DATA, protocol, param, ERRC_SUCCESS, (strlen(transferParam) + 1), (uint8_t*)transferParam);

	if (!quietMode)
		fprintf(stdout, "Sending data packet (file name)...\n");

	stnc_print_packet_data((stnc_packet*)buffer);

	if (stnc_send_tcp_data(chatSocket, buffer, false) == -1)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to send data packet.\n");

		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "Data packet sent.\n"
						"Waiting for ACK packet...\n");

	if (stnc_receive_tcp_data(chatSocket, buffer, false) == -1 || stnc_get_packet_type(buffer) != MSGT_ACK)
	{
		fprintf(stderr, "Failed to receive ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet received.\n"
						"Starting file transfer...\n");

	int ret = perf_client_ipv4(data_to_send, chatSocket, FILE_SIZE, ip, portNumber, param, quietMode);

	if (ret <= 0)
	{
		fprintf(stderr, "Failed to transfer file.\n");
		free(data_to_send);
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
	{
		fprintf(stdout, "File transfer complete.\n"
						"Sent total of %d bytes (%d KB, %d MB).\n", ret, (ret / 1024), (ret / (1024 * 1024)));
	}

	stnc_prepare_packet(buffer, MSGT_ACK, protocol, param, ERRC_SUCCESS, 0, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending ACK packet...\n");

	if (stnc_send_tcp_data(chatSocket, buffer, false) == -1)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to send ACK packet.\n");

		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet sent.\n"
					"Waiting for statistics packet...\n");

	if (stnc_receive_tcp_data(chatSocket, buffer, false) == -1 || stnc_get_packet_type(buffer) != MSGT_DATA)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to receive statistics packet.\n");

		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "Statistics packet received.\n");

	stnc_print_packet_payload((stnc_packet*)buffer);

	stnc_prepare_packet(buffer, MSGT_END, protocol, param, ERRC_SUCCESS, 0, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending end packet...\n");

	if (stnc_send_tcp_data(chatSocket, buffer, false) == -1)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to send end packet.\n");

		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "End packet sent.\n"
						"Closing connection and cleaning up memory...\n");

	close(chatSocket);
	free(data_to_send);

	if (!quietMode)
		fprintf(stdout, "Memory cleanup complete.\n"
						"Connection closed.\n"
						"Exiting...\n");

	return EXIT_SUCCESS;
}

int server_performance_mode(char *port, bool quietMode) {
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
	
	int actual_received = 0;

	int chatSocket = INVALID_SOCKET, serverSocket = INVALID_SOCKET, reuse = 1;

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

	fprintf(stdout, "Waiting for connection...\n");

	if ((chatSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength)) < 0)
	{
		perror("accept");
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Connection established with %s:%d\n", inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));

	if (!quietMode)
		fprintf(stdout, "Waiting for initilization packet...\n");

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

		char* err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, protocol, param, ERRC_ALLOC, (strlen(err) + 1), (uint8_t *)err);
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

	// TODO START

	// Add file transfer code here
	actual_received = perf_server_ipv4(chatSocket, data_to_receive, fileSize, portNumber, param, quietMode);

	if (actual_received == -1)
	{
		fprintf(stderr, "Failed to receive data packet.\n");
		free(data_to_receive);
		close(chatSocket);
		return EXIT_FAILURE;
	}

	// TODO END

	fprintf(stdout, "File transfer complete.\n");

	md5Hash = md5_calculate_checksum(data_to_receive, actual_received);

	if (md5Hash == NULL)
	{
		fprintf(stderr, "Failed to calculate MD5 checksum.\n");
		free(data_to_receive);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "MD5 checksum of received data: %s\n", md5Hash);

	free(md5Hash);

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
						"Waiting for ACK packet...\n");

	if (stnc_receive_tcp_data(chatSocket, buffer, quietMode) == -1 || stnc_get_packet_type(buffer) != MSGT_ACK)
	{
		fprintf(stderr, "Failed to receive ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet received.\n");

	// Calculate transfer time here and whatever...

	stnc_prepare_packet(buffer, MSGT_DATA, protocol, param, ERRC_SUCCESS, 0, NULL);

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

int perf_client_ipv4(uint8_t* data, int chatsocket, uint32_t filesize, char *server_ip, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	struct sockaddr_in serverAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int serverSocket = INVALID_SOCKET;

	uint32_t bytesSent = 0;

	memset(&serverAddress, 0, sizeof(serverAddress));

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(server_port + 1);

	inet_pton(AF_INET, server_ip, &serverAddress.sin_addr);

	if ((serverSocket = socket(AF_INET, (param == PARAM_TCP) ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0)
	{
		if (!quietMode)
			perror("socket");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return EXIT_FAILURE;
	}

	if (param == PARAM_TCP)
	{
		if (connect(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		{
			if (!quietMode)
				perror("connect");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);
			
			return -1;
		}

		if (!quietMode)
			fprintf(stdout, "Connection established with %s:%d\n", server_ip, server_port);
	}

	struct pollfd fds[2];

	fds[0].fd = chatsocket;
	fds[0].events = POLLIN;
	fds[1].fd = serverSocket;
	fds[1].events = POLLOUT;

	while (bytesSent < filesize)
	{
		int ret = poll(fds, 2, STNC_POLL_TIMEOUT);

		if (ret < 0)
		{
			if (!quietMode)
				perror("poll");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SEND, (strlen(err) + 1), (uint8_t *) err);
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

		if (fds[0].revents & POLLIN)
		{
			stnc_receive_tcp_data(chatsocket, buffer, quietMode);

			if (stnc_get_packet_error(buffer) != ERRC_SUCCESS)
			{
				if (!quietMode)
					fprintf(stderr, "Error packet received.\n");

				stnc_print_packet_data((stnc_packet *)buffer);

				close(serverSocket);

				return -1;
			}
		}

		if (fds[1].revents & POLLOUT)
		{
			if (!quietMode && (bytesSent % (CHUNK_SIZE * 8) == 0))
				fprintf(stdout, "Sending data packet (%u KB/%u KB)...\n", bytesSent / 1024, filesize / 1024);

			if (param == PARAM_TCP)
			{
				uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

				int bytes = send(serverSocket, data + bytesSent, bytesToSend, 0);

				if (bytes == -1)
				{
					if (!quietMode)
						fprintf(stderr, "Failed to send data packet.\n");

					char *err = strerror(errno);

					stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SEND, (strlen(err) + 1), (uint8_t *) err);
					stnc_send_tcp_data(chatsocket, buffer, quietMode);

					close(serverSocket);

					return -1;
				}

				bytesSent += bytes;
			}

			else
			{
				uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE_UDP) ? CHUNK_SIZE_UDP:(filesize - bytesSent));

				int bytes = sendto(serverSocket, data + bytesSent, bytesToSend, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress));

				if (bytes == -1)
				{
					if (!quietMode)
						perror("sendto");

					char *err = strerror(errno);

					stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SEND, (strlen(err) + 1), (uint8_t *) err);
					stnc_send_tcp_data(chatsocket, buffer, quietMode);

					close(serverSocket);

					return -1;
				}

				bytesSent += bytes;
			}
		}
	}

	if (!quietMode && param == PARAM_TCP)
		fprintf(stdout, "Closing connection with %s:%d\n", server_ip, server_port);

	close(serverSocket);

	return bytesSent;
}

int perf_client_ipv6(uint8_t* data, int chatsocket, uint32_t filesize, char *server_ip, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	struct sockaddr_in6 serverAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int serverSocket = INVALID_SOCKET;

	uint32_t bytesSent = 0;

	memset(&serverAddress, 0, sizeof(serverAddress));

	serverAddress.sin6_family = AF_INET6;
	serverAddress.sin6_port = htons(server_port + 1);

	inet_pton(AF_INET6, server_ip, &serverAddress.sin6_addr);

	if ((serverSocket = socket(AF_INET6, (param == PARAM_TCP) ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0)
	{
		if (!quietMode)
			perror("socket");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if (param == PARAM_TCP)
	{
		if (connect(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		{
			if (!quietMode)
				perror("connect");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			return -1;
		}

		if (!quietMode)
			fprintf(stdout, "Connection established with %s:%d\n", server_ip, server_port);
	}

	while (bytesSent < filesize)
	{
		if (!quietMode)
			fprintf(stdout, "Sending data packet (%u/%u)...\n", bytesSent, filesize);
		
		uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

		int bytes = (param == PARAM_TCP ? send(serverSocket, data + bytesSent, CHUNK_SIZE, bytesToSend):sendto(serverSocket, data + bytesSent, CHUNK_SIZE, bytesToSend, (struct sockaddr *)&serverAddress, sizeof(serverAddress)));

		if (bytes == -1)
		{
			if (!quietMode)
				fprintf(stderr, "Failed to send data packet.\n");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_IPV6, param, ERRC_SEND, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		bytesSent += (uint32_t)bytes;
	}

	if (!quietMode && param == PARAM_TCP)
		fprintf(stdout, "Closing connection with %s:%d\n", server_ip, server_port);

	close(serverSocket);

	return bytesSent;	
}

int perf_client_unix(uint8_t* data, int chatsocket, uint32_t filesize, char *server_uds_path, stnc_transfer_param param, bool quietMode) {
	struct sockaddr_un serverAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int serverSocket = INVALID_SOCKET;
	
	socklen_t len = strlen(server_uds_path) + sizeof(serverAddress.sun_family);

	uint32_t bytesSent = 0;

	memset(&serverAddress, 0, sizeof(serverAddress));

	serverAddress.sun_family = AF_UNIX;
	strcpy(serverAddress.sun_path, server_uds_path);

	if ((serverSocket = socket(AF_UNIX, (param == PARAM_STREAM) ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0)
	{
		if (!quietMode)
			perror("socket");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if (param == PARAM_STREAM)
	{
		if (connect(serverSocket, (struct sockaddr *)&serverAddress, len) < 0)
		{
			if (!quietMode)
				perror("connect");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			return -1;
		}

		if (!quietMode)
			fprintf(stdout, "Connection established with \"%s\"\n", server_uds_path);
	}

	while (bytesSent < filesize)
	{
		if (!quietMode)
			fprintf(stdout, "Sending data packet (%u/%u)...\n", bytesSent, filesize);
		
		uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

		int bytes = (param == PARAM_STREAM ? send(serverSocket, data + bytesSent, CHUNK_SIZE, bytesToSend):sendto(serverSocket, data + bytesSent, CHUNK_SIZE, bytesToSend, (struct sockaddr *)&serverAddress, sizeof(serverAddress)));

		if (bytes == -1)
		{
			if (!quietMode)
				fprintf(stderr, "Failed to send data packet.\n");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_UNIX, param, ERRC_SEND, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			close(serverSocket);
			return -1;
		}

		bytesToSend += (uint32_t)bytes;
	}

	if (!quietMode)
		fprintf(stdout, "Closing connection with \"%s\"\n", server_uds_path);

	close(serverSocket);

	return bytesSent;
}

int perf_client_memory(int chatsocket, char* file_name, uint8_t *dataToSend, uint32_t filesize, bool quietMode) {
	uint8_t *data = MAP_FAILED;
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	int fd = INVALID_SOCKET;

	if ((fd = open(file_name, O_RDWR)) == -1)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to open file \"%s\"\n", file_name);

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if ((data = mmap(NULL, sizeof(uint32_t) + filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		if (!quietMode)
			perror("mmap");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		close(fd);
		return -1;
	}

	uint32_t *sentSize = (uint32_t *)data;
	data += sizeof(uint32_t);

	uint32_t bytesSent = 0;

	while (bytesSent < filesize)
	{
		uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

		memcpy(data + bytesSent, dataToSend + bytesSent, bytesToSend);

		bytesSent += bytesToSend;
		*sentSize = bytesSent;
	}

	if (munmap(data, sizeof(uint32_t) + filesize) == -1)
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

	return bytesSent;
}

int perf_client_pipe(int chatsocket, char* fifo_name, uint8_t *dataToSend, uint32_t filesize, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int fd = INVALID_SOCKET;

	uint32_t bytesSent = 0;

	if (mkfifo(fifo_name, 0666) == -1)
	{
		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_PIPE, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	if ((fd = open(fifo_name, O_WRONLY)) == -1)
	{
		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_PIPE, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	while (bytesSent < filesize)
	{
		uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

		write(fd, dataToSend + bytesSent, bytesToSend);

		bytesSent += bytesToSend;
	}

	close(fd);

	return bytesSent;
}

int perf_server_ipv4(int chatsocket, uint8_t* data, uint32_t filesize, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	struct sockaddr_in serverAddress, clientAddress;
	socklen_t len = sizeof(clientAddress);

	uint32_t bytesReceived = 0;

	int serverSocket = INVALID_SOCKET, reuse = 1;

	if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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
	serverAddress.sin_port = htons(server_port + 1);

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
			fprintf(stdout, "Sending ACK to client to connect...\n");

		stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_IPV4, param, ERRC_SUCCESS, 0, NULL);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		if (!quietMode)
			fprintf(stdout, "ACK sent, waiting for client to connect...\n");

		int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &len);

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
			int ret = poll(fds, 2, STNC_POLL_TIMEOUT);

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
				if (!quietMode && (bytesReceived % (CHUNK_SIZE * 8) == 0))
					fprintf(stdout, "Receiving data packet (%u KB/%u KB)...\n", bytesReceived / 1024, filesize / 1024);

				uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived));

				int bytes = 0;

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
			fprintf(stdout, "ACK sent, waiting for client to start sending data...\n");

		while (bytesReceived < filesize)
		{
			int ret = poll(fds, 2, STNC_POLL_TIMEOUT * 5);

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

			if (fds[0].revents & POLLIN)
			{
				if (!quietMode)
					fprintf(stderr, "Sender finished sending data. Stop receiving data.\n");

				stnc_receive_tcp_data(chatsocket, buffer, quietMode);
				stnc_print_packet_data((stnc_packet *)buffer);

				break;
			}

			else if (fds[1].revents & POLLIN)
			{
				if (!quietMode && (bytesReceived % (CHUNK_SIZE * 8) == 0))
					fprintf(stdout, "Receiving data packet (%u KB/%u KB)...\n", bytesReceived / 1024, filesize / 1024);

				uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE_UDP) ? CHUNK_SIZE_UDP:(filesize - bytesReceived));

				int bytes = 0;

				bytes = recvfrom(serverSocket, data + bytesReceived, bytesToReceive, 0, (struct sockaddr *)&clientAddress, &len);

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
		}

		close(serverSocket);
	}

	if (!quietMode)
		fprintf(stdout, "Received %u bytes.\n", bytesReceived);

	return bytesReceived;
}

int perf_server_ipv6(int chatsocket, uint8_t* data, uint32_t filesize, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	struct sockaddr_in6 serverAddress, clientAddress;
	socklen_t len = sizeof(clientAddress);

	uint32_t bytesReceived = 0;

	int serverSocket = INVALID_SOCKET;

	if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		if (!quietMode)
			perror("socket");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return EXIT_FAILURE;
	}

	memset(&serverAddress, 0, sizeof(serverAddress));
	memset(&clientAddress, 0, sizeof(clientAddress));

	serverAddress.sin6_family = AF_INET6;
	serverAddress.sin6_port = htons(server_port + 1);
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

		int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &len);

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
			char clientIP[INET6_ADDRSTRLEN] = { 0 };

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

			fprintf(stdout, "Client connected from %s:%d.\n", clientIP, ntohs(clientAddress.sin6_port));
		}

		close(serverSocket);

		while (bytesReceived < filesize)
		{
			uint32_t bytesToReceive = (((filesize - bytesReceived) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesReceived));

			int bytes = 0;

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

			int bytes = 0;

			if (!quietMode)
				fprintf(stdout, "Receiving data packet (%u/%u)...\n", bytesReceived, filesize);

			bytes = recvfrom(serverSocket, data + bytesReceived, bytesToReceive, 0, (struct sockaddr *)&clientAddress, &len);

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
		fprintf(stdout, "Received %u bytes.\n", bytesReceived);

	return bytesReceived;
}

int perf_server_unix(int chatsocket, uint8_t* data, uint32_t filesize, char *server_uds_path, stnc_transfer_param param, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	struct sockaddr_un serverAddress, clientAddress = {
        .sun_family = AF_UNIX,
    };

	uint32_t bytesReceived = 0;

	socklen_t clientAddressLength = sizeof(clientAddress);

	int serverSocket = INVALID_SOCKET;

	int len = sizeof(struct sockaddr_un) + strlen(server_uds_path);

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

		int clientSocket = INVALID_SOCKET;

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

			int bytes = 0;

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

			int bytes = 0;

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

int perf_server_memory(int chatsocket, uint8_t* data, uint32_t filesize, char* file_name, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	uint8_t *dataToReceive = MAP_FAILED;

	int fd = INVALID_SOCKET;

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

int perf_server_pipe(int chatsocket, uint8_t* data, uint32_t filesize, char* file_name, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	int fd = INVALID_SOCKET;

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