/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Utilities
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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/evp.h>

/*
 * @brief The signeture of the data, used to identify the data as STNC data.
 * @note The signeture is 64 bytes long, and is composed of the following:
 * 		  	Magic number (STNC in ASCII), the word SPEEDTEST in ASCII,
 * 		  	the names ROY_SIMANOVICH and LINOR_RONEN in ASCII,
 * 		  	and the word ARIEL_OPSYS_HW3_MAY23 in ASCII.
*/
const uint8_t data_signeture[] = 
{ 
	0x53, 0x54, 0x4E, 0x43, 0x00, 0x53, 0x50, 0x45,
	0x45, 0x44, 0x54, 0x45, 0x53, 0x54, 0x00, 0x52,
	0x4F, 0x59, 0x5F, 0x53, 0x49, 0x4D, 0x41, 0x4E,
	0x4F, 0x56, 0x49, 0x43, 0x48, 0x5F, 0x4C, 0x49,
	0x4E, 0x4F, 0x52, 0x5F, 0x52, 0x4F, 0x4E, 0x45,
	0x4E, 0x00, 0x41, 0x52, 0x49, 0x45, 0x4C, 0x5F,
	0x4F, 0x50, 0x53, 0x59, 0x53, 0x5F, 0x48, 0x57,
	0x33, 0x5F, 0x4D, 0x41, 0x59, 0x32, 0x33, 0x00
};

void stnc_print_usage(char *programName, uint8_t mode){
	switch(mode)
	{
		case 0:
		{
			fprintf(stdout, "Student Network Communication (STNC) usage:\n");
			fprintf(stdout, "Client mode: %s -c <ip> <port> [-p <type> <param>]\n", programName);
			fprintf(stdout, "Server mode: %s -s <port> [-p] [-q]\n", programName);
			break;
		}

		case 1:
		{
			fprintf(stdout, "Usage: %s -c <ip> <port> [-p <type> <param>]\n", programName);
			break;
		}

		case 2:
		{
			fprintf(stdout, "Usage: %s -s <port> [-p] [-q]\n", programName);
			break;
		}

		default: break;
	}
}

void stnc_print_license() {
	fprintf(stdout, "Student Network Communication (STNC)  Copyright (C) 2023  Roy Simanovich and Linor Ronen\n"
					"This program comes with ABSOLUTELY NO WARRANTY.\n"
					"This is free software, and you are welcome to redistribute it\n"
					"under certain conditions; see `LICENSE' for details.\n\n");

}

uint8_t *util_generate_random_data(uint32_t size, bool quietMode) {
	uint8_t *buffer = NULL;

	if (size == 0)
		return NULL;

	buffer = (uint8_t *)calloc(size, sizeof(uint8_t));

	if (buffer == NULL)
		return NULL;

	// Randomize the seed of the random number generator
	srand(time(NULL));

	if (!quietMode)
		fprintf(stdout, "Generating %u bytes (%u MB) of random data...\n", size, (size / 1024 / 1024));

	memcpy(buffer, data_signeture, sizeof(data_signeture));

	for (uint32_t i = sizeof(data_signeture); i < size; i++)
		*(buffer + i) = ((uint32_t)rand() % 256);

	if (!quietMode)
		fprintf(stdout, "Successfully generated %u bytes (%u MB) of random data.\n", size, (size / 1024 / 1024));

	return buffer;
}

stnc_transfer_protocol stnc_get_transfer_protocol(char *transferType) {
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

stnc_transfer_param stnc_get_transfer_param(char *transferParam) {
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

int32_t stnc_print_packet_data(stnc_packet *packet) {
	static const char *packetTypes[] = { "Initalization", "Acknowledgement", "Data transfer", "End communication" };
	static const char *transferProtocols[] = { "None", "IPv4", "IPv6", "Unix Domain Socket (UDS)", "Memory Mapped File (MMAP)", "Named Pipe (FIFO)" };
	static const char *transferParams[] = { "None", "Transmission Control Protocol (TCP)", "User Datagram Protocol (UDP)", "Stream", "Datagram", "File" };
	static const char *errorCodes[] = { "Success (No error)", "Socket error", "Send error", "Receive error", "Memory Mapping error", "Piping error", "Allocation error" };

	if (packet == NULL)
	{
		fprintf(stderr, "Invalid packet.\n");
		return 1;
	}

	fprintf(stdout, "----------------------------------------\n");
	fprintf(stdout, "Packet type: %s\n"
					"Transfer protocol: %s\n"
					"Transfer param: %s\n"
					"Error code: %s\n"
					"Size: %u bytes\n",
					packetTypes[packet->type], 
					transferProtocols[packet->protocol],
					transferParams[packet->param],
					errorCodes[packet->error],
					packet->size
			);
	
	if (packet->type == MSGT_DATA && packet->size > 0)
	{
		uint8_t *ptr = (uint8_t *)packet + sizeof(stnc_packet);

		fprintf(stdout, "Data: ");

		for (uint32_t i = 0; i < packet->size; i++)
			fputc(*(ptr + i), stdout);

		fprintf(stdout, "\n");
	}
	fprintf(stdout, "----------------------------------------\n");

	return 0;
}

int32_t stnc_print_packet_payload(stnc_packet *packet) {
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

	uint8_t *ptr = (uint8_t *)packet + sizeof(stnc_packet);

	for (uint32_t i = 0; i < packet->size; i++)
		fputc(*(ptr + i), stdout);

	fprintf(stdout, "\n");

	return 0;
}

int32_t stnc_prepare_packet(uint8_t *buffer, stnc_message_type type, stnc_transfer_protocol protocol, stnc_transfer_param param, stnc_error_code error, uint32_t size, uint8_t *data) {
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

int32_t stnc_send_tcp_data(int32_t socket, uint8_t *packet, bool quietMode) {
	int32_t bytesToSend = 0;

	if (((stnc_packet *)packet)->type == MSGT_DATA)
		bytesToSend = sizeof(stnc_packet) + ((stnc_packet *)packet)->size;

	else
		bytesToSend = sizeof(stnc_packet);

	if ((uint32_t)bytesToSend > STNC_PROTO_MAX_SIZE + sizeof(stnc_packet))
	{
		if (!quietMode)
			fprintf(stderr, "Invalid data size (%d/%d).\n", bytesToSend, STNC_PROTO_MAX_SIZE);

		return -1;
	}
	
	int32_t bytesSent = send(socket, packet, bytesToSend, 0);

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

int32_t stnc_receive_tcp_data(int32_t socket, uint8_t *packet, bool quietMode) {
	ssize_t bytesReceived = recv(socket, packet, (STNC_PROTO_MAX_SIZE + sizeof(stnc_packet)), 0);

	if (bytesReceived < 0)
	{
		if (!quietMode)
			perror("recv()");

		return -1;
	}

	else if (bytesReceived == 0)
	{
		if (!quietMode)
			fprintf(stderr, "Connection closed by the peer.\n");

		return -1;
	}

	else if ((size_t)bytesReceived < sizeof(stnc_packet))
	{
		if (!quietMode)
			fprintf(stderr, "Received packet is too small.\n");

		return -1;
	}

	else if (((stnc_packet *)packet)->size > STNC_PROTO_MAX_SIZE && ((stnc_packet *)packet)->type == MSGT_DATA)
	{
		if (!quietMode)
			fprintf(stderr, "Received packet is too big.\n");

		return -1;
	}
	
	else if (!quietMode)
		fprintf(stdout, "Received %lu bytes.\n", bytesReceived);

	if (stnc_get_packet_error(packet) != ERRC_SUCCESS)
	{
		if (!quietMode)
		{
			uint8_t *error = packet + sizeof(stnc_packet);
			fprintf(stderr, "Received packet contains an error:\n");
			fprintf(stderr, "Error code: %u\n", stnc_get_packet_error(packet));
			fprintf(stderr, "Error message: %s\n", error);
		}

		else
			fprintf(stderr, "STNC internal error, please disable quiet mode to see the error message.\n");

		return -2;
	}

	return bytesReceived;
}

stnc_message_type stnc_get_packet_type(uint8_t *buffer) {
	if (buffer == NULL)
		return MSGT_INVALID;

	return ((stnc_packet *)buffer)->type;
}

stnc_transfer_protocol stnc_get_packet_protocol(uint8_t *buffer) {
	if (buffer == NULL)
		return PROTOCOL_NONE;

	return ((stnc_packet *)buffer)->protocol;
}

stnc_transfer_param stnc_get_packet_param(uint8_t *buffer) {
	if (buffer == NULL)
		return PARAM_NONE;

	return ((stnc_packet *)buffer)->param;
}

stnc_error_code stnc_get_packet_error(uint8_t *buffer) {
	if (buffer == NULL)
		return ERRC_INVALID;

	return ((stnc_packet *)buffer)->error;
}

uint32_t stnc_get_packet_size(uint8_t *buffer) {
	if (buffer == NULL)
		return 0;

	return ((stnc_packet *)buffer)->size;
}

char* util_md5_checksum(uint8_t *data, uint32_t size) {
	EVP_MD_CTX *mdctx;

	uint8_t *md5_digest = NULL;
	char *checksumString = NULL;

	uint32_t md5_digest_len = EVP_MD_size(EVP_md5());
    
	// MD5_Init
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

	// MD5_Update
	EVP_DigestUpdate(mdctx, data, size);

	// MD5_Final
	md5_digest = (uint8_t *)OPENSSL_malloc(md5_digest_len);
	EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
	EVP_MD_CTX_free(mdctx);

	checksumString = (char *)calloc((md5_digest_len * 2 + 1), sizeof(int8_t));

	if (checksumString == NULL)
	{
		fprintf(stderr, "Failed to allocate memory for checksum string.\n");
		OPENSSL_free(md5_digest);
		return NULL;
	}

	for (uint32_t i = 0; i < md5_digest_len; i++)
		sprintf(checksumString + (i * 2), "%02x", md5_digest[i]);

	OPENSSL_free(md5_digest);

	return checksumString;
}
bool util_is_valid_data(uint8_t *data, uint32_t size) {
	if (data == NULL || size < 64)
		return false;

	for (uint32_t i = 0; i < 64; i++)
	{
		if (*(data + i) != *(data_signeture + i))
			return false;
	}

	return true;
}