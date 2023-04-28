/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Header File
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

#ifndef _STNC_H
#define _STNC_H

/*
 * @brief Client chat mode of the STNC program.
 * @param ip The IP address of the server.
 * @param port The port number of the server.
 * @return 0 on success, 1 on failure.
*/
int client_chat_mode(char *ip, char *port);

/*
 * @brief Server chat mode of the STNC program.
 * @param port The port number of the server.
 * @return 0 on success, 1 on failure.
*/
int server_chat_mode(char *port);


/*
 * @brief Prints the usage of the STNC program (General usage).
 * @param programName The name of the program.
 * @return void (no return value).
 * @note This function is used by the main function of the STNC program.
*/
void printUsage(char *programName);

/*
 * @brief Prints the usage of the STNC program in client mode.
 * @param programName The name of the program.
 * @return void (no return value).
 * @note This function is used by the main function of the STNC program.
*/
void printClientUsage(char *programName);

/*
 * @brief Prints the usage of the STNC program in server mode.
 * @param programName The name of the program.
 * @return void (no return value).
 * @note This function is used by the main function of the STNC program.
*/
void printServerUsage(char *programName);

/*
 * @brief Prints the license of the STNC program.
 * @return void (no return value).
 * @note This function is used by the main function of the STNC program.
*/
void printLicense();

#endif