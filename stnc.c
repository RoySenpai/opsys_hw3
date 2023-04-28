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
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "stnc.h"

int main(int argc, char **argv) {
	printLicense();

	if (argc < 2)
	{
		printUsage(*argv);
		return EXIT_FAILURE;
	}

	else if (strcmp(*(argv + 1), "-c") == 0)
	{
		if (argc < 4)
		{
			printClientUsage(*argv);
			return EXIT_FAILURE;
		}

		return client_chat_mode(*(argv + 2), *(argv + 3));
	}

	else if (strcmp(*(argv + 1), "-s") == 0)
	{
		if (argc < 3)
		{
			printServerUsage(*argv);
			return EXIT_FAILURE;
		}

		return server_chat_mode(*(argv + 2));
	}

	else
	{
		printUsage(*argv);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

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
						"under certain conditions; see `LICENSE' for details.\n\n"
		);
}

int client_chat_mode(char *ip, char *port) {
	fprintf(stdout, "Client mode: %s %s\n", ip, port);

	return EXIT_SUCCESS;
}

int server_chat_mode(char *port) {
	fprintf(stdout, "Server mode: %s\n", port);

	return EXIT_SUCCESS;
}