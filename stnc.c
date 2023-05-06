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

#include "stnc.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
	stnc_print_license();

	if (argc < 2)
	{
		stnc_print_usage(*argv, 0);
		return EXIT_FAILURE;
	}

	else if (strcmp(*(argv + 1), "-c") == 0)
	{
		if (argc < 4 || argc > 7)
		{
			stnc_print_usage(*argv, 1);
			return EXIT_FAILURE;
		}

		else if (argc == 4)
		{
			fprintf(stdout, "Client chat mode\n");
			return stnc_client_chat(*(argv + 2), *(argv + 3));
		}

		else if (strcmp(*(argv + 4), "-p") == 0)
		{
			if (argc != 7)
			{
				stnc_print_usage(*argv, 1);
				return EXIT_FAILURE;
			}

			fprintf(stdout, "Client performance mode\n");
			return stnc_client_performance(*(argv + 2), *(argv + 3), *(argv + 5), *(argv + 6), CLIENT_QUIET_MODE);
		}

		else
		{
			stnc_print_usage(*argv, 1);
			return EXIT_FAILURE;
		}
	}

	else if (strcmp(*(argv + 1), "-s") == 0)
	{
		if (argc < 3 || argc > 5)
		{
			stnc_print_usage(*argv, 2);
			return EXIT_FAILURE;
		}

		else if (argc == 3)
		{
			fprintf(stdout, "Server chat mode\n");
			return stnc_server_chat(*(argv + 2));
		}

		else if (strcmp(*(argv + 3), "-p") == 0)
		{
			bool quietmode = false;

			if (argc != 4 && argc != 5)
			{
				stnc_print_usage(*argv, 2);
				return EXIT_FAILURE;
			}

			else if (argc == 5)
			{
				if (strcmp(*(argv + 4), "-q") == 0)
					quietmode = true;

				else
				{
					stnc_print_usage(*argv, 2);
					return EXIT_FAILURE;
				}
			}

			fprintf(stdout, "Server performance mode\n");

			if (quietmode)
				fprintf(stdout, "Quiet mode enabled\n");
				
			return stnc_server_performance(*(argv + 2), quietmode);
		}

		else
		{
			stnc_print_usage(*argv, 2);
			return EXIT_FAILURE;
		}
	}

	else
	{
		stnc_print_usage(*argv, 0);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
