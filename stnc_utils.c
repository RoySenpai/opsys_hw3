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
#include <string.h>
#include <sys/types.h>
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

int generateRandomData(char *file_name, uint64_t size) {
    FILE *fd = NULL;
    uint8_t *buffer = NULL;
    uint64_t remainingBytes = size;

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

	fprintf(stdout, "Generating %lu bytes (%lu MB) of random data...\n", size, (size / 1024 / 1024));
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

	fprintf(stdout, "Successfully generated %lu bytes (%lu MB) of random data.\n", size, (size / 1024 / 1024));

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