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

#include "stnc_protocol.h"
#include "stnc_utils.h"

/*************************/
/* Functions declaration */
/*************************/

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
 * @brief Client performance mode of the STNC program.
 * @param ip The IP address of the server.
 * @param port The port number of the server.
 * @param transferType The type of the transfer.
 * @param transferProtocol The protocol of the transfer.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
 * @note This function is used by the main function of the STNC program.
*/
int client_performance_mode(char *ip, char *port, char *transferType, char *transferProtocol, bool quietMode);

/*
 * @brief Server performance mode of the STNC program.
 * @param port The port number of the server.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
 * @note This function is used by the main function of the STNC program.
*/
int server_performance_mode(char *port, bool quietMode);

/*
 * @brief Client side of the performance mode of the STNC program - IPv4.
 * @param data The data to transfer.
 * @param chatsocket The socket to use for communication.
 * @param filesize The size of the file to transfer.
 * @param server_ip The IP address of the server.
 * @param server_port The port of the server.
 * @param param The transfer parameter (TCP or UDP).
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_client_ipv4(uint8_t* data, int chatsocket, uint32_t filesize, char *server_ip, uint16_t server_port, stnc_transfer_param param, bool quietMode);

/*
 * @brief Client side of the performance mode of the STNC program - IPv6.
 * @param data The data to transfer.
 * @param chatsocket The socket to use for communication.
 * @param filesize The size of the file to transfer.
 * @param server_ip The IP address of the server.
 * @param server_port The port of the server.
 * @param param The transfer parameter (TCP or UDP).
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_client_ipv6(uint8_t* data, int chatsocket, uint32_t filesize, char *server_ip, uint16_t server_port, stnc_transfer_param param, bool quietMode);

/*
 * @brief Client side of the performance mode of the STNC program - Unix Socket Domain.
 * @param data The data to transfer.
 * @param chatsocket The socket to use for communication.
 * @param filesize The size of the file to transfer.
 * @param server_uds_path The path of the server (Unix Domain Socket).
 * @param param The transfer parameter (TCP or UDP).
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_client_unix(uint8_t* data, int chatsocket, uint32_t filesize, char *server_uds_path, stnc_transfer_param param, bool quietMode);

/*
 * @brief Client side of the performance mode of the STNC program - Memory Mapping Sharing.
 * @param chatsocket The socket to use for communication.
 * @param file_name The name of the file to write to memory.
 * @param dataToSend The data to transfer.
 * @param filesize The size of the file to transfer.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_client_memory(int chatsocket, char* file_name, uint8_t *dataToSend, uint32_t filesize, bool quietMode);

/*
 * @brief Client side of the performance mode of the STNC program - Pipe (FIFO)
 * @param chatsocket The socket to use for communication.
 * @param fifo_name The name of the pipe to write to.
 * @param dataToSend The data to transfer.
 * @param filesize The size of the file to transfer.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_client_pipe(int chatsocket, char* fifo_name, uint8_t *dataToSend, uint32_t filesize, bool quietMode);

/*
 * @brief Server side of the performance mode of the STNC program - IPv4.
 * @param chatsocket The socket to use for communication.
 * @param data The data to transfer.
 * @param filesize The size of the file to transfer.
 * @param server_port The port of the server.
 * @param param The transfer parameter (TCP or UDP).
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_server_ipv4(int chatsocket, uint8_t* data, uint32_t filesize, uint16_t server_port, stnc_transfer_param param, bool quietMode);

/*
 * @brief Server side of the performance mode of the STNC program - IPv6.
 * @param chatsocket The socket to use for communication.
 * @param data The data to transfer.
 * @param filesize The size of the file to transfer.
 * @param server_port The port of the server.
 * @param param The transfer parameter (TCP or UDP).
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_server_ipv6(int chatsocket, uint8_t* data, uint32_t filesize, uint16_t server_port, stnc_transfer_param param, bool quietMode);

/*
 * @brief Server side of the performance mode of the STNC program - Unix Socket Domain.
 * @param chatsocket The socket to use for communication.
 * @param data The data to transfer.
 * @param filesize The size of the file to transfer.
 * @param server_uds_path The path of the server (Unix Domain Socket).
 * @param param The transfer parameter (Stream or Datagram).
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_server_unix(int chatsocket, uint8_t* data, uint32_t filesize, char *server_uds_path, stnc_transfer_param param, bool quietMode);

/*
 * @brief Server side of the performance mode of the STNC program - Memory Mapping Sharing.
 * @param chatsocket The socket to use for communication.
 * @param data The data to transfer.
 * @param filesize The size of the file to transfer.
 * @param file_name The name of the file to read from.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_server_memory(int chatsocket, uint8_t* data, uint32_t filesize, char* file_name, bool quietMode);

/*
 * @brief Server side of the performance mode of the STNC program - Pipe (FIFO)
 * @param chatsocket The socket to use for communication.
 * @param data The data to transfer.
 * @param filesize The size of the file to transfer.
 * @param file_name The name of the file to read from.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
*/
int perf_server_pipe(int chatsocket, uint8_t* data, uint32_t filesize, char* file_name, bool quietMode);

#endif