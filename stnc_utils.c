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
#include "stnc.h"

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

int generateRandomData(char *file_name, uint32_t size) {
    FILE *fd = NULL;
    uint8_t *buffer = NULL;
    uint32_t remainingBytes = size;

    if (remainingBytes == 0)
	{
		fprintf(stderr, "Invalid size.\n");
		return EXIT_FAILURE;
	}

    if (isFileExists(file_name))
    {
        fprintf(stderr, "File already exists.\n");
        return EXIT_FAILURE;
    }

    if (strcmp(file_name, "") == 0)
    {
        fprintf(stderr, "Invalid file name.\n");
        return EXIT_FAILURE;
    }

    fd = fopen(file_name, "wb");

	if (fd == NULL)
	{
		fprintf(stderr, "Invalid file descriptor.\n");
		return EXIT_FAILURE;
	}

    buffer = (uint8_t *)calloc(CHUNK_SIZE, sizeof(uint8_t));

    if (buffer == NULL)
    {
        fprintf(stderr, "Failed to allocate memory.\n");
        fclose(fd);
        return EXIT_FAILURE;
    }

	fprintf(stdout, "Generating %u bytes (%u MB) of random data...\n", size, (size / 1024 / 1024));
	fprintf(stdout, "Chunk size: %d bytes (%d KB)\n", CHUNK_SIZE, (CHUNK_SIZE / 1024));

	while (remainingBytes > 0)
	{
		uint32_t bytesToWrite = ((remainingBytes > CHUNK_SIZE) ? CHUNK_SIZE:remainingBytes);

		for (uint32_t i = 0; i < bytesToWrite; i++)
			*(buffer + i) = rand() % 256;

		if (fwrite(buffer, sizeof(char), bytesToWrite, fd) != bytesToWrite)
		{
			fprintf(stderr, "Failed to write to file.\n");
			return EXIT_FAILURE;
		}

		remainingBytes -= bytesToWrite;
	}

	fprintf(stdout, "Successfully generated %u bytes (%u MB) of random data.\n", size, (size / 1024 / 1024));

    free(buffer);
    fclose(fd);

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

int printPacketData(stnc_packet *packet) {
	static const char *packetTypes[] = { "Initalization", "Acknowledgement", "Data transfer", "End communication" };
	static const char *transferProtocols[] = { "None", "IPv4", "IPv6", "Unix domain socket", "Memory mapped file", "Pipe" };
	static const char *transferParams[] = { "None", "TCP", "UDP", "Stream", "Datagram", "File" };
	static const char *errorCodes[] = { "Success", "Socket error", "Send error", "Receive error", "Memory Mapping error", "Piping error", "Thread error" };

	if (packet == NULL)
	{
		fprintf(stderr, "Invalid packet.\n");
		return 1;
	}

	fprintf(stdout, "----------------------------------------\n");
	fprintf(stdout, "Packet type: %s\n", packetTypes[packet->type]);
	fprintf(stdout, "Transfer protocol: %s\n", transferProtocols[packet->protocol]);
	fprintf(stdout, "Transfer param: %s\n", transferParams[packet->param]);
	fprintf(stdout, "Error code: %s\n", errorCodes[packet->error]);
	fprintf(stdout, "Size: %u bytes\n", packet->size);
	
	if (packet->type == MSGT_DATA && packet->size > 0)
	{
		uint8_t *ptr = (uint8_t *)packet;
		ptr += sizeof(stnc_packet);

		fprintf(stdout, "Data: ");

		for (uint32_t i = 0; i < packet->size; i++)
			fputc(*(ptr + i), stdout);

		fprintf(stdout, "\n");
	}
	fprintf(stdout, "----------------------------------------\n");

	return 0;
}

int printPacketPayload(stnc_packet *packet) {
	if (packet == NULL)
	{
		fprintf(stderr, "Invalid packet.\n");
		return 1;
	}

	else if (packet->size == 0 || packet->type != MSGT_DATA)
	{
		fprintf(stderr, "Packet has no payload.\n");
		return 1;
	}

	else if (packet->size > STNC_PROTO_MAX_SIZE)
	{
		fprintf(stderr, "Invalid data size (%u/%u).\n", packet->size, STNC_PROTO_MAX_SIZE);
		return 1;
	}

	uint8_t *ptr = (uint8_t *)packet;

	for (uint32_t i = 0; i < packet->size; i++)
		fputc(*(ptr + i), stdout);

	fprintf(stdout, "\n");

	return 0;
}

int PreparePacket(uint8_t *buffer, message_type type, transfer_protocol protocol, transfer_param param, error_code error, uint32_t size, uint8_t *data) {
	if (buffer == NULL)
	{
		fprintf(stderr, "Invalid packet.\n");
		return 1;
	}
	
	else if (size > STNC_PROTO_MAX_SIZE && data != NULL)
	{
		fprintf(stderr, "Invalid data size (%u/%u).\n", size, STNC_PROTO_MAX_SIZE);
		return 1;
	}

	stnc_packet *packet = (stnc_packet *)buffer;

	packet->type = type;
	packet->protocol = protocol;
	packet->param = param;
	packet->error = error;
	packet->size = size;

	if (data != NULL && size > 0)
		memcpy(buffer + sizeof(stnc_packet), data, size);

	return 0;
}

int sendTCPData(int socket, uint8_t *packet, bool quietMode) {
	int bytesToSend = 0;

	if (((stnc_packet *)packet)->type == MSGT_DATA)
		bytesToSend = sizeof(stnc_packet) + ((stnc_packet *)packet)->size;

	else
		bytesToSend = sizeof(stnc_packet);
	
	int bytesSent = send(socket, packet, bytesToSend, 0);

	if (bytesSent <= 0)
	{
		if (!quietMode)
			perror("send()");

		return -1;
	}

	else if (bytesSent != bytesToSend)
	{
		if (!quietMode)
			fprintf(stderr, "Failed to send all data. Sent %d bytes out of %d.\n", bytesSent, bytesToSend);

		return -1;
	}

	if (!quietMode)
		fprintf(stdout, "Sent %d bytes.\n", bytesSent);

	return bytesSent;
}

int receiveTCPData(int socket, uint8_t *packet, bool quietMode) {
	ssize_t bytesReceived = recv(socket, packet, STNC_PROTO_MAX_SIZE, 0);

	if (bytesReceived < 0)
	{
		if (!quietMode)
			perror("recv()");

		return -1;
	}

	else if (bytesReceived == 0)
	{
		if (!quietMode)
			fprintf(stderr, "Connection closed by the remote host.\n");

		return -1;
	}

	else if ((size_t)bytesReceived < sizeof(stnc_packet))
	{
		if (!quietMode)
			fprintf(stderr, "Received packet is too small.\n");

		return -1;
	}

	else if (bytesReceived > STNC_PROTO_MAX_SIZE)
	{
		if (!quietMode)
			fprintf(stderr, "Received packet is too large.\n");
		
		return -1;
	}

	else if (!quietMode)
		fprintf(stdout, "Received %lu bytes.\n", bytesReceived);

	if (GetPacketError(packet) != ERRC_SUCCESS)
	{
		if (!quietMode)
		{
			uint8_t *error = packet + sizeof(stnc_packet);
			fprintf(stderr, "Received packet contains an error:\n");
			fprintf(stderr, "Error code: %u\n", GetPacketError(packet));
			fprintf(stderr, "Error message: %s\n", error);
		}

		return -1;
	}

	return bytesReceived;
}

message_type GetPacketType(uint8_t *buffer) {
	if (buffer == NULL)
		return MSGT_INVALID;

	return ((stnc_packet *)buffer)->type;
}

transfer_protocol GetPacketProtocol(uint8_t *buffer) {
	if (buffer == NULL)
		return PROTOCOL_NONE;

	return ((stnc_packet *)buffer)->protocol;
}

transfer_param GetPacketParam(uint8_t *buffer) {
	if (buffer == NULL)
		return PARAM_NONE;

	return ((stnc_packet *)buffer)->param;
}

error_code GetPacketError(uint8_t *buffer) {
	if (buffer == NULL)
		return ERRC_INVALID;

	return ((stnc_packet *)buffer)->error;
}

uint32_t GetPacketSize(uint8_t *buffer) {
	if (buffer == NULL)
		return 0;

	return ((stnc_packet *)buffer)->size;
}