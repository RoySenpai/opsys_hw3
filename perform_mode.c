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
	transfer_protocol protocol = getTransferProtocol(transferProtocol);
	transfer_param param = getTransferParam(transferParam);

	if (protocol == PROTOCOL_NONE || (param == PARAM_NONE && protocol != PROTOCOL_MMAP && protocol != PROTOCOL_PIPE))
	{
		fprintf(stderr, "Invalid transfer protocol or transfer param.\n");
		return EXIT_FAILURE;
	}

	if (protocol == PROTOCOL_MMAP || protocol == PROTOCOL_PIPE)
		param = PARAM_FILE;

	if (!isFileExists(((protocol == PROTOCOL_MMAP || protocol == PROTOCOL_PIPE) ? transferParam:FILE_NAME)))
	{
		fprintf(stdout, "File \"%s\" not found. Generating random data...\n", ((protocol == PROTOCOL_MMAP || protocol == PROTOCOL_PIPE) ? transferParam:FILE_NAME));
		
		if (generateRandomData(((protocol == PROTOCOL_MMAP || protocol == PROTOCOL_PIPE) ? transferParam:FILE_NAME), FILE_SIZE) == EXIT_FAILURE)
		{
			fprintf(stderr, "Failed to generate random data.\n");
			return EXIT_FAILURE;
		}
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