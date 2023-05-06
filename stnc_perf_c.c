/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Performance Mode - Client
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

// Indicating that we are using POSIX 2008, for the use of the function "fileno".
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "stnc.h"

int32_t stnc_client_performance(char *ip, char *port, char *transferProtocol, char *transferParam, bool quietMode) {
	struct sockaddr_in serverAddress;
	struct timeval start, end;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	uint8_t *data_to_send = NULL;

	int32_t chatSocket = INVALID_SOCKET;
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

	data_to_send = util_generate_random_data(FILE_SIZE);

	if (data_to_send == NULL)
	{
		fprintf(stderr, "Failed to generate random data.\n");
		return EXIT_FAILURE;
	}

	char *md5 = util_md5_checksum(data_to_send, FILE_SIZE);

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
		fprintf(stdout, "ACK packet received.\n");

	fprintf(stdout, "Starting transfer...\n");

	int32_t ret = 0;

	gettimeofday(&start, NULL);
	
	switch(protocol)
	{
		case PROTOCOL_IPV4:
		{
			ret = stnc_perf_client_ipv4(data_to_send, chatSocket, FILE_SIZE, ip, (portNumber + 1), param, quietMode);
			break;
		}

		case PROTOCOL_IPV6:
		{
			// Local IPv6 address, loopback.
			// TODO: Add support for other IPv6 addresses.
			char ipv6Address[] = "::1";
			ret = stnc_perf_client_ipv6(data_to_send, chatSocket, FILE_SIZE, ipv6Address, (portNumber + 1), param, quietMode);
			break;
		}

		case PROTOCOL_UNIX:
		{
			ret = stnc_perf_client_unix(data_to_send, chatSocket, FILE_SIZE, STNC_UNIX_NAME, param, quietMode);
			break;
		}

		case PROTOCOL_MMAP:
		{
			ret = stnc_perf_client_memory(chatSocket, transferParam, data_to_send, FILE_SIZE, quietMode);
			break;
		}

		default:
		{
			fprintf(stderr, "Invalid protocol.\n");
			free(data_to_send);
			close(chatSocket);
			return EXIT_FAILURE;
		}
	}

	if (ret <= 0)
	{
		fprintf(stderr, "Failed to transfer file.\n");
		free(data_to_send);
		close(chatSocket);
		return EXIT_FAILURE;
	}

	gettimeofday(&end, NULL);

	fprintf(stdout, "File transfer complete.\n"
					"Sent total of %d bytes (%d KB, %d MB).\n", ret, (ret / 1024), (ret / (1024 * 1024)));

	double transferTime = (double)(end.tv_sec - start.tv_sec) + ((double)(end.tv_usec - start.tv_usec) / 1000000);

	fprintf(stdout, "Transfer time: %.2f seconds.\n"
					"Transfer speed: %.2f KB/s.\n", transferTime, ((double)ret / 1024) / transferTime);

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

	stnc_print_packet_payload((stnc_packet *)buffer);

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

int32_t stnc_perf_client_ipv4(uint8_t* data, int32_t chatsocket, uint32_t filesize, char *server_ip, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	struct sockaddr_in serverAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int32_t serverSocket = INVALID_SOCKET;

	socklen_t len = sizeof(serverAddress);

	uint32_t bytesSent = 0;

	memset(&serverAddress, 0, sizeof(serverAddress));

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(server_port);

	if (inet_pton(AF_INET, server_ip, &serverAddress.sin_addr) <= 0)
	{
		if (!quietMode)
			perror("inet_pton");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	} 

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
		int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

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
			if (param == PARAM_TCP)
			{
				uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

				int32_t bytes = send(serverSocket, data + bytesSent, bytesToSend, 0);

				if (bytes <= 0)
				{
					if (!quietMode)
						perror("send");

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
				
				int32_t bytes = sendto(serverSocket, data + bytesSent, bytesToSend, 0, (struct sockaddr *)&serverAddress, len);

				if (bytes <= 0)
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

int32_t stnc_perf_client_ipv6(uint8_t* data, int32_t chatsocket, uint32_t filesize, char *server_ip, uint16_t server_port, stnc_transfer_param param, bool quietMode) {
	struct sockaddr_in6 serverAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int32_t serverSocket = INVALID_SOCKET;

	uint32_t bytesSent = 0;

	memset(&serverAddress, 0, sizeof(serverAddress));

	serverAddress.sin6_family = AF_INET6;
	serverAddress.sin6_port = htons(server_port);

	if (inet_pton(AF_INET6, server_ip, &serverAddress.sin6_addr) <= 0)
	{
		if (!quietMode)
			perror("inet_pton");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SOCKET, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return EXIT_FAILURE;
	}

	if ((serverSocket = socket(AF_INET6, (param == PARAM_TCP) ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0)
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
		int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

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
			if (param == PARAM_TCP)
			{
				uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

				int32_t bytes = send(serverSocket, data + bytesSent, bytesToSend, 0);

				if (bytes <= 0)
				{
					if (!quietMode)
						perror("send");

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
				
				int32_t bytes = sendto(serverSocket, data + bytesSent, bytesToSend, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress));

				if (bytes <= 0)
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

int32_t stnc_perf_client_unix(uint8_t* data, int32_t chatsocket, uint32_t filesize, char *server_uds_path, stnc_transfer_param param, bool quietMode) {
	struct sockaddr_un serverAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int32_t serverSocket = INVALID_SOCKET;
	
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

	struct pollfd fds[2];

	fds[0].fd = chatsocket;
	fds[0].events = POLLIN;
	fds[1].fd = serverSocket;
	fds[1].events = POLLOUT;

	while (bytesSent < filesize)
	{
		int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

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
			if (param == PARAM_STREAM)
			{
				uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

				int32_t bytes = send(serverSocket, data + bytesSent, bytesToSend, 0);

				if (bytes <= 0)
				{
					if (!quietMode)
						perror("send");

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
				
				int32_t bytes = sendto(serverSocket, data + bytesSent, bytesToSend, 0, (struct sockaddr *)&serverAddress, len);

				if (bytes <= 0)
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
		fprintf(stdout, "Closing connection with \"%s\"\n", server_uds_path);

	close(serverSocket);

	return bytesSent;
}

int32_t stnc_perf_client_memory(int32_t chatsocket, char *file_name, uint8_t *dataToSend, uint32_t filesize, bool quietMode) {
	uint8_t *data = MAP_FAILED;
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };

	int32_t fd = INVALID_SOCKET;

	FILE *fp = NULL;

	if ((fp = fopen(file_name, "w+")) == NULL)
	{
		char *err = strerror(errno);

		if (!quietMode)
			fprintf(stderr, "Failed to open file \"%s\": %s\n", file_name, err);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		return -1;
	}

	fd = fileno(fp);

	ftruncate(fd, filesize);

	if ((data = mmap(NULL, sizeof(uint32_t) + filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		if (!quietMode)
			perror("mmap");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		fclose(fp);
		return -1;
	}

	uint8_t *dataPtr = data;
	uint32_t bytesSent = 0;

	struct pollfd fds[2];

	fds[0].fd = chatsocket;
	fds[0].events = POLLIN;
	fds[1].fd = fd;
	fds[1].events = POLLOUT;

	if (!quietMode)
		fprintf(stdout, "Sending ACK to server to start sending data...\n");

	stnc_prepare_packet(buffer, MSGT_ACK, PROTOCOL_MMAP, PARAM_FILE, ERRC_SUCCESS, 0, NULL);
	stnc_send_tcp_data(chatsocket, buffer, quietMode);

	if (!quietMode)
		fprintf(stdout, "ACK sent, starting sending data...\n");

	while (bytesSent < filesize)
	{
		int32_t ret = poll(fds, 2, STNC_POLL_TIMEOUT);

		if (ret < 0)
		{
			if (!quietMode)
				perror("poll");

			char *err = strerror(errno);

			stnc_prepare_packet(buffer, MSGT_DATA, 0, 0, ERRC_SEND, (strlen(err) + 1), (uint8_t *) err);
			stnc_send_tcp_data(chatsocket, buffer, quietMode);

			munmap(data, sizeof(uint32_t) + filesize);
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

			munmap(data, sizeof(uint32_t) + filesize);
			fclose(fp);

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

				munmap(data, sizeof(uint32_t) + filesize);
				fclose(fp);

				return -1;
			}
		}

		else if (fds[1].revents & POLLOUT)
		{
			uint32_t bytesToSend = (((filesize - bytesSent) > CHUNK_SIZE) ? CHUNK_SIZE:(filesize - bytesSent));

			memcpy(dataPtr, dataToSend, bytesToSend);

			dataToSend += bytesToSend;
			dataPtr += bytesToSend;

			bytesSent += bytesToSend;
		}
	}

	if (munmap(data, sizeof(uint32_t) + filesize) == -1)
	{
		if (!quietMode)
			perror("munmap");

		char *err = strerror(errno);

		stnc_prepare_packet(buffer, MSGT_DATA, PROTOCOL_MMAP, PARAM_FILE, ERRC_MMAP, (strlen(err) + 1), (uint8_t *) err);
		stnc_send_tcp_data(chatsocket, buffer, quietMode);

		fclose(fp);
		return -1;
	}

	fclose(fp);

	if (!quietMode)
		fprintf(stdout, "Memory mapped file \"%s\" sent successfully.\n", file_name);

	return bytesSent;
}

int32_t stnc_perf_client_pipe(int32_t chatsocket, char *fifo_name, uint8_t *dataToSend, uint32_t filesize, bool quietMode) {
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int32_t fd = INVALID_SOCKET;

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
