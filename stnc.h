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

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

/**********************/
/* Macros declaration */
/**********************/

/*
 * @brief A macro to indicate an invalid socket.
*/
#define INVALID_SOCKET -1

/*
 * @breif Defines the minimum port number that can be used by the STNC program.
 * @note The default value is 1024.
 * @note The maximum port number is 65535.
*/
#define MIN_PORT_NUMBER 1024


/*
 * @brief Defines the maximum size of a message, in chat mode.
 * @note The default value is 1024 bytes.
*/
#define MAX_MESSAGE_SIZE 1024


/*
 * @brief Defines the chunk size of the generated file, in performance mode.
 * @note The default value is 65536 bytes.
*/
#define CHUNK_SIZE 65536

/*
 * @brief Defines the File name for the performance mode.
 * @note The default value is "stnc_file".
*/
#define FILE_NAME "stnc_file"

/*
 * @brief Defines the File size for the performance mode.
 * @note The default value is 100MB (104,857,600 bytes).
*/
#define FILE_SIZE 104857600

/*
 * @brief Defines the type of the message for the performace test.
*/
typedef enum __attribute__((__packed__)) _message_type {

	/* Initialization - communication started, exchange transfer type. */
	MSGT_INIT = 0,

	/* Acknowledgement - transfer type received, ready to start. */
	MSGT_ACK,

	/* Data - data transfer. */
	MSGT_DATA,

	/* End - communication ended. */
	MSGT_END,

	/* Error - error occurred. */
	MSGT_ERR
} message_type;

/*
 * @brief Defines the protocol of the transfer for the performace test.
 * @note This protocol is used to indicate the type of the transfer.
 * @note For TCP and UDP, the protocol is either PROTOCOL_IPV4 or PROTOCOL_IPV6 only.
 * @note For stream and datagram sockets, the protocol is PROTOCOL_UNIX only.
 * @note PROTOCOL_NONE is used for error.
*/
typedef enum __attribute__((__packed__)) _transfer_protocol {
	/* No protocol - Error */
	PROTOCOL_NONE = -1,

	/* IPv4 transfer */
	PROTOCOL_IPV4 = 0,

	/* IPv6 transfer */
	PROTOCOL_IPV6,

	/* Unix socket transfer */
	PROTOCOL_UNIX,

	/* Shared memory transfer */
	PROTOCOL_MMAP,

	/* Pipe transfer */
	PROTOCOL_PIPE
} transfer_protocol;

/*
 * @brief Defines the parameter of the transfer for the performace test.
 * @note This parameter is used to indicate the type of the transfer.
 * @note For mmap and pipe, the parameter is always PARAM_NONE.
*/
typedef enum __attribute__((__packed__)) _transfer_param {
	/* No parameter - Error/indicates a file name */
	PARAM_NONE = -1,

	/* TCP transfer */
	PARAM_TCP = 0,

	/* UDP transfer */
	PARAM_UDP,

	/* Stream socket transfer */
	PARAM_STREAM,

	/* Datagram socket transfer */
	PARAM_DGRAM,

	/* File transfer via shared memory or pipe */
	PARAM_FILE
} transfer_param;


/*
 * @brief Defines the error codes for the performace test.
*/
typedef enum __attribute__((__packed__)) _error_code {
	/* No error, normal operation */
	ERRC_SUCCESS = 0,

	/* Socket error */
	ERRC_SOCKET,

	/* Error in send() or sendto() */
	ERRC_SEND,

	/* Error in recv() or recvfrom() */
	ERRC_RECV,

	/* Error in MMAP */
	ERRC_MMAP,

	/* Error in Pipe */
	ERRC_PIPE,

	/* Error in thread */
	ERRC_THREAD
} error_code;


/*
 * @brief Defines the message structure for the performace test.
 * @note This structure is used to send messages between the client and the server.
 * @note The message structure is used only for the performance test.
 * @note This is a custom protocol, and not a standard protocol, we call it the STNC protocol.
 * @note STNC header size is 16 bytes.
*/
typedef struct __STNC_PACKET {
	/* The type of the message. */
	message_type type;

	/* The protocol of the transfer. Only valid for MSGT_INIT. */
	transfer_protocol protocol;

	/* The parameter of the transfer. Only valid for MSGT_INIT. */
	transfer_param param;

	/* The error code. Only valid for MSGT_ERR. */
	error_code error;

	/* 
	 * @brief The size of the payload.
	 * @note If the message is MSGT_INIT, this is the size of the file that will be sent.
	 * @note If the message is MSGT_DATA, this is the size of the data itself (without the header).
	 * @note In all other cases, this should be 0 always.
	*/
	uint64_t size;
} stnc_packet;

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
 * @return 0 on success, 1 on failure.
 * @note This function is used by the main function of the STNC program.
*/
int client_performance_mode(char *ip, char *port, char *transferType, char *transferProtocol);

/*
 * @brief Server performance mode of the STNC program.
 * @param port The port number of the server.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return 0 on success, 1 on failure.
 * @note This function is used by the main function of the STNC program.
*/
int server_performance_mode(char *port, bool quietMode);


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

/*
 * @brief Generates random data for the performace test, according to the given size.
 * @param fd The file descriptor of the file to write the data to.
 * @param size The size of the data buffer.
 * @return 0 on success, 1 on failure.
 * @note The data is generated using the rand() function.
 * @note The data is generated in blocks of 64KB.
 * @note If the size is not a multiple of 64KB, the last block will be smaller.
*/
int generateRandomData(char *file_name, uint64_t size);

/*
 * @brief Checks if a file exists.
 * @param filename The name of the file to check.
 * @return true if the file exists, false otherwise.
 * @note This function is used by the performance mode of the STNC program.
*/
bool isFileExists(char *filename);

/*
 * @brief Returns the transfer type according to the given string.
 * @param transferType The string to check.
 * @return The transfer type according to the given string.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given string is not a valid transfer type, PROTOCOL_NONE is returned.
*/
transfer_protocol getTransferProtocol(char *transferType);

/*
 * @brief Returns the transfer protocol according to the given string.
 * @param transferProtocol The string to check.
 * @return The transfer protocol according to the given string.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given string is not a valid transfer protocol, PROTOCOL_NONE is returned.
*/
transfer_param getTransferParam(char *transferParam);

#endif