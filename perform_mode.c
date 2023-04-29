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

int client_performance_mode(char *ip, char *port, char *transferProtocol, char *transferParam) {
	char fileName[FILE_NAME_MAX_SIZE] = { 0 };
	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	int chatSocket = INVALID_SOCKET;
	uint16_t portNumber = atoi(port);
	transfer_protocol protocol = getTransferProtocol(transferProtocol);
	transfer_param param = getTransferParam(transferParam);

	strcpy(fileName, ((protocol == PROTOCOL_MMAP || protocol == PROTOCOL_PIPE) ? transferParam:FILE_NAME));

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

	if (!isFileExists(fileName))
	{
		fprintf(stdout, "File \"%s\" not found. Generating random data...\n", fileName);
		
		if (generateRandomData(fileName, FILE_SIZE) == EXIT_FAILURE)
		{
			fprintf(stderr, "Failed to generate random data.\n");
			return EXIT_FAILURE;
		}
	}

	struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(portNumber);

	if (inet_pton(AF_INET, ip, &serverAddress.sin_addr) <= 0)
	{
		perror("inet_pton");
		return EXIT_FAILURE;
	}

	if ((chatSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		perror("socket");
		return EXIT_FAILURE;
	}

	if (connect(chatSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		perror("connect");
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Connected to server %s:%d.\n", ip, portNumber);

	fprintf(stdout, "Transfer protocol: %s\n"
	 				"Transfer param: %s\n"
					"File name: %s\n"
					"File size: %d\n", 
					transferProtocol, transferParam, fileName, FILE_SIZE);

	PreparePacket(buffer, MSGT_INIT, protocol, param, ERRC_SUCCESS, FILE_SIZE, NULL);

	fprintf(stdout, "Sending initilization packet (file size, protocol, param)...\n");

	if (sendTCPData(chatSocket, buffer, false) == -1)
	{
		fprintf(stderr, "Failed to send initilization packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Initilization packet sent.\n"
					"Waiting for ACK packet...\n");

	if (receiveTCPData(chatSocket, buffer, false) == -1 || GetPacketType(buffer) != MSGT_ACK)
	{
		fprintf(stderr, "Failed to receive ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "ACK packet received.\n");

	PreparePacket(buffer, MSGT_DATA, protocol, param, ERRC_SUCCESS, (strlen(fileName) + 1), (uint8_t*)fileName);

	fprintf(stdout, "Sending data packet (file name)...\n");

	printPacketData((stnc_packet*)buffer);

	if (sendTCPData(chatSocket, buffer, false) == -1)
	{
		fprintf(stderr, "Failed to send data packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Data packet sent.\n"
					"Waiting for ACK packet...\n");

	if (receiveTCPData(chatSocket, buffer, false) == -1 || GetPacketType(buffer) != MSGT_ACK)
	{
		fprintf(stderr, "Failed to receive ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "ACK packet received.\n");

	// TODO START 
	
	// This is where we send the file via the appropriate protocol
	
	// TODO END

	
	fprintf(stdout, "Waiting for ACK packet...\n");

	if (receiveTCPData(chatSocket, buffer, false) == -1 || GetPacketType(buffer) != MSGT_ACK)
	{
		fprintf(stderr, "Failed to receive ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "ACK packet received.\n"
					"File transfer complete.\n");

	PreparePacket(buffer, MSGT_ACK, protocol, param, ERRC_SUCCESS, 0, NULL);

	fprintf(stdout, "Sending ACK packet...\n");

	if (sendTCPData(chatSocket, buffer, false) == -1)
	{
		fprintf(stderr, "Failed to send ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "ACK packet sent.\n"
					"Waiting for statistics packet...\n");

	if (receiveTCPData(chatSocket, buffer, false) == -1 || GetPacketType(buffer) != MSGT_DATA)
	{
		fprintf(stderr, "Failed to receive statistics packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Statistics packet received.\n");

	printPacketPayload((stnc_packet*)buffer);

	PreparePacket(buffer, MSGT_END, protocol, param, ERRC_SUCCESS, 0, NULL);

	fprintf(stdout, "Sending end packet...\n");

	if (sendTCPData(chatSocket, buffer, false) == -1)
	{
		fprintf(stderr, "Failed to send end packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "End packet sent.\n"
					"Closing connection...\n");

	close(chatSocket);

	return EXIT_SUCCESS;
}

int server_performance_mode(char *port, bool quietMode) {
	struct sockaddr_in serverAddress, clientAddress;

	uint8_t buffer[STNC_PROTO_MAX_SIZE] = { 0 };
	char fileName[STNC_PROTO_MAX_SIZE] = { 0 };

	stnc_packet *packetData = (stnc_packet *)buffer;

	socklen_t clientAddressLength = sizeof(clientAddress);
	uint16_t portNumber = atoi(port);

	transfer_protocol protocol = PROTOCOL_NONE;
	transfer_param param = PARAM_NONE;
	uint32_t fileSize = 0;

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

	if (receiveTCPData(chatSocket, buffer, quietMode) == -1 || GetPacketType(buffer) != MSGT_INIT)
	{
		fprintf(stderr, "Failed to receive initilization packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	protocol = GetPacketProtocol(buffer);
	param = GetPacketParam(buffer);
	fileSize = GetPacketSize(buffer);

	if (!quietMode)
	{
		fprintf(stdout, "Initilization packet received.\n"
						"Protocol: %u\n"
						"Param: %u\n"
						"File size: %u\n", protocol, param, fileSize);
	}

	PreparePacket(buffer, MSGT_ACK, protocol, param, ERRC_SUCCESS, 0, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending ACK packet...\n");

	if (sendTCPData(chatSocket, buffer, quietMode) == -1)
	{
		fprintf(stderr, "Failed to send ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet sent.\n"
						"Waiting for data packet (file name)...\n");

	if (receiveTCPData(chatSocket, buffer, quietMode) == -1 || GetPacketType(buffer) != MSGT_DATA)
	{
		fprintf(stderr, "Failed to receive data packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
	{
		fprintf(stdout, "Data packet received.\n");
		printPacketData(packetData);
	}

	strcpy(fileName, ((char *)packetData + sizeof(stnc_packet)));

	PreparePacket(buffer, MSGT_ACK, protocol, param, ERRC_SUCCESS, 0, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending ACK packet...\n");

	if (sendTCPData(chatSocket, buffer, quietMode) == -1)
	{
		fprintf(stderr, "Failed to send ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet sent.\n");

	fprintf(stdout, "Starting file transfer...\n");

	// TODO START

	// Add file transfer code here

	// TODO END

	fprintf(stdout, "File transfer complete.\n");

	PreparePacket(buffer, MSGT_ACK, protocol, param, ERRC_SUCCESS, 0, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending ACK packet...\n");

	if (sendTCPData(chatSocket, buffer, quietMode) == -1)
	{
		fprintf(stderr, "Failed to send ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet sent.\n"
						"Waiting for ACK packet...\n");

	if (receiveTCPData(chatSocket, buffer, quietMode) == -1 || GetPacketType(buffer) != MSGT_ACK)
	{
		fprintf(stderr, "Failed to receive ACK packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "ACK packet received.\n");

	// Calculate transfer time here and whatever...

	PreparePacket(buffer, MSGT_DATA, protocol, param, ERRC_SUCCESS, 0, NULL);

	if (!quietMode)
		fprintf(stdout, "Sending statistics packet...\n");

	if (sendTCPData(chatSocket, buffer, quietMode) == -1)
	{
		fprintf(stderr, "Failed to send statistics packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
		fprintf(stdout, "Statistics packet sent.\n"
						"Waiting for end packet...\n");

	if (receiveTCPData(chatSocket, buffer, quietMode) == -1 || GetPacketType(buffer) != MSGT_END)
	{
		fprintf(stderr, "Failed to receive end packet.\n");
		close(chatSocket);
		return EXIT_FAILURE;
	}

	if (!quietMode)
	{
		fprintf(stdout, "End packet received.\n");
		printPacketData(packetData);
	}

	fprintf(stdout, "Closing connection...\n");
	close(chatSocket);
	close(serverSocket);


	return EXIT_SUCCESS;
}