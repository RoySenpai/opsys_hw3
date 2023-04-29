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
 * @brief Defines the maximum size of a file name, in performance mode.
 * @note The default value is 256 characters.
*/
#define FILE_NAME_MAX_SIZE 256

/*
 * @brief Defines the maximum size of a message, in performance mode.
 * @note The default value is 1024 bytes.
*/
#define STNC_PROTO_MAX_SIZE 1024


/****************************/
/* Enumerations declaration */
/****************************/

/*
 * @brief Defines the type of the message for the performace test.
*/
typedef enum __attribute__((__packed__)) _message_type {
	/* 
	 * @brief Invalid - invalid message type.
	 * @note This message is used to indicate an invalid message type.
	 * @note Used internally by the STNC program, and not sent over the network.
	*/
	MSGT_INVALID = -1,

	/* 
	 * @brief Initialization - communication started, exchange transfer type.
	 * @note This message is sent only once, at the beginning of the communication.
	 * @note This message is sent by the client only.
	*/
	MSGT_INIT = 0,

	/* 
	 * @brief Acknowledgement - transfer type received, ready to start. 
	 * @note This message can be sent multiple times, in different stages of the communication.
	 * @note This message can be sent by both the client and the server.
	*/
	MSGT_ACK,

	/* 
	 * @brief Data - data transfer.
	 * @note This message indicates that data is being sent (statistics, file name, address, etc.).
	 * @note Errors are sent as data messages.
	*/
	MSGT_DATA,

	/* 
	 * @brief End - communication ended. 
	 * @note This message is sent only once, at the end of the communication.
	 * @note This message is sent by the client only (the server will close the connection upon receiving this message).
	*/
	MSGT_END
} message_type;

/*
 * @brief Defines the protocol of the transfer for the performace test.
 * @note This protocol is used to indicate the type of the transfer.
 * @note For TCP and UDP, the protocol is either PROTOCOL_IPV4 or PROTOCOL_IPV6 only.
 * @note For stream and datagram sockets, the protocol is PROTOCOL_UNIX only.
 * @note PROTOCOL_NONE is used for error.
*/
typedef enum __attribute__((__packed__)) _transfer_protocol {
	/* 
	 * @brief No protocol - Invalid protocol.
	 * @note This indicates an error by providing an invalid protocol, in the client side.
	*/
	PROTOCOL_NONE = 0,

	/*
	 * @brief IPv4 protocol - TCP/UDP transfer.
	 * @note This indicates that the transfer is either TCP or UDP in IPv4.
	*/
	PROTOCOL_IPV4 = 1,

	/*
	 * @brief IPv6 protocol - TCP/UDP transfer.
	 * @note This indicates that the transfer is either TCP or UDP in IPv6.
	*/
	PROTOCOL_IPV6,

	/*
	 * @brief Unix protocol - Stream/Datagram socket transfer.
	 * @note This indicates that the transfer is either stream or datagram socket in Unix domain.
	 * @note Can only work in the same machine, as it uses the file system.
	*/
	PROTOCOL_UNIX,

	/*
	 * @brief Shared memory protocol - Shared memory transfer.
	 * @note This indicates that the transfer is shared memory.
	 * @note Can only work in the same machine, as it uses the file system.
	*/
	PROTOCOL_MMAP,

	/*
	 * @brief Pipe protocol - Pipe transfer.
	 * @note This indicates that the transfer is pipe.
	 * @note Can only work in the same machine, as it uses the file system.
	*/
	PROTOCOL_PIPE
} transfer_protocol;

/*
 * @brief Defines the parameter of the transfer for the performace test.
 * @note This parameter is used to indicate the type of the transfer.
 * @note For mmap and pipe, the parameter is always PARAM_NONE.
*/
typedef enum __attribute__((__packed__)) _transfer_param {
	/* 
	 * @brief No parameter - Invalid parameter.
	 * @note This indicates an error by providing an invalid parameter, in the client side, if the protocol isn't mmap or pipe.
	*/
	PARAM_NONE = 0,

	/*
	 * @brief TCP parameter - TCP transfer.
	 * @note This indicates that the transfer is TCP.
	 * @note Only valid for IPv4 and IPv6 protocols.
	*/
	PARAM_TCP = 1,

	/*
	 * @brief UDP parameter - UDP transfer.
	 * @note This indicates that the transfer is UDP.
	 * @note Only valid for IPv4 and IPv6 protocols.
	*/
	PARAM_UDP,

	/* 
	 * @brief Stream parameter - Stream socket transfer.
	 * @note This indicates that the transfer is stream socket.
	 * @note Only valid for Unix protocol.
	*/
	PARAM_STREAM,

	/* 
	 * @brief Datagram parameter - Datagram socket transfer.
	 * @note This indicates that the transfer is datagram socket.
	 * @note Only valid for Unix protocol.
	*/
	PARAM_DGRAM,

	/*
	 * @brief File parameter - File transfer.
	 * @note This indicates that the transfer is file.
	 * @note Only valid for mmap and pipe protocols.
	*/
	PARAM_FILE
} transfer_param;


/*
 * @brief Defines the error codes for the performace test.
 * @note This error code is used to indicate the type of the error.
 * @note The error code also provides a short description of the error, as a string payload in the message.
*/
typedef enum __attribute__((__packed__)) _error_code {

	/* 
	 * @brief Invalid - invalid error code.
	 * @note This error is used to indicate an invalid error code.
	 * @note Used internally by the STNC program, and not sent over the network.
	*/
	ERRC_INVALID = -1,

	/* 
	 * @brief Success - No error, normal operation.
	 * @note This indicates that the operation was successful.
	 * @note This is the only error code that doesn't have a string payload.
	*/
	ERRC_SUCCESS = 0,

	/*
	 * @brief Socket - Socket error.
	 * @note This indicates that an error occurred in the socket itself.
	*/
	ERRC_SOCKET,

	/*
	 * @brief Send - Error in send() or sendto().
	 * @note This indicates that an error occurred in the send() or sendto() functions.
	*/
	ERRC_SEND,

	/*
	 * @brief Recv - Error in recv() or recvfrom().
	 * @note This indicates that an error occurred in the recv() or recvfrom() functions.
	*/
	ERRC_RECV,

	/*
	 * @brief MMAP - Error in MMAP.
	 * @note This indicates that an error occurred in one of the mmap() functions.
	*/
	ERRC_MMAP,

	/*
	 * @brief Pipe - Error in Pipe.
	 * @note This indicates that an error occurred in one of the pipe() functions.
	*/
	ERRC_PIPE,

	/*
	 * @brief Thread - Error in thread.
	 * @note This indicates that an error occurred in one of the pthread functions.
	*/
	ERRC_THREAD
} error_code;


/*
 * @brief Defines the message structure for the performace test.
 * @note This structure is used to send messages between the client and the server.
 * @note The message structure is used only for the performance test.
 * @note This is a custom protocol, and not a standard protocol, we call it the STNC protocol.
 * @note STNC header size is 8 bytes.
*/
typedef struct __STNC_PACKET {
	/* 
	 * @brief The type of the message.
	 * @note This field is mandatory for all messages.
	 * @note Field size is 1 byte.
	*/
	message_type type;

	/* 
	 * @brief The protocol of the transfer.
	 * @note This field is mandatory for all messages, and shouldn't change during the transfer.
	 * @note Field size is 1 byte.
	*/
	transfer_protocol protocol;

	/* 
	 * @brief The parameter of the transfer.
	 * @note This field is mandatory for all messages, and shouldn't change during the transfer.
	 * @note Field size is 1 byte.
	*/
	transfer_param param;

	/* 
	 * @brief The error code.
	 * @note If the error code isn't ERRC_SUCCESS, an error message will be sent as a string payload.
	 * @note Incase of an error, both parties should close the connection immediately, preventing any further communication.
	 * @note Field size is 1 byte.
	*/ 
	error_code error;

	/* 
	 * @brief The size of the payload.
	 * @note For MSGT_INIT, there isn't a payload, so this field is used to indicate the size of the file.
	 * @note For MSGT_DATA, this is the size of the payload itself.
	 * @note In all other cases, this should be 0 always, as there is no payload.
	 * @note Field size is 4 bytes.
	*/
	uint32_t size;
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
int generateRandomData(char *file_name, uint32_t size);

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

/*
 * @brief Prints the given packet data.
 * @param packet The packet to print.
 * @return 0 on success, 1 on failure.
 * @note This function is used by the performance mode of the STNC program.
*/
int printPacketData(stnc_packet *packet);

/*
 * @brief Prepares a packet according to the given parameters.
 * @param buffer The buffer to write the packet to.
 * @param type The type of the packet.
 * @param protocol The protocol of the packet.
 * @param param The parameter of the packet.
 * @param error The error code of the packet.
 * @param size The size of the payload (can be 0 if no payload is needed).
 * @param data The payload of the packet (can be NULL if no payload is needed).
 * @return 0 on success, 1 on failure.
*/
int PreparePacket(uint8_t *buffer, message_type type, transfer_protocol protocol, transfer_param param, error_code error, uint32_t size, uint8_t *data);

/*
 * @brief Sends the given packet to the given socket.
 * @param socket The socket to send the packet to.
 * @param packet The packet to send.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return number of bytes sent on success, -1 on failure.
*/
int sendTCPData(int socket, uint8_t *packet, bool quietMode);

/*
 * @brief Receives a packet from the given socket.
 * @param socket The socket to receive the packet from.
 * @param packet The packet to receive.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return number of bytes received on success, -1 on failure.
*/
int receiveTCPData(int socket, uint8_t *packet, bool quietMode);

/*
 * @brief Retrieves the type of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The type of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, MSGT_INVALID is returned.
*/
message_type GetPacketType(uint8_t *buffer);

/*
 * @brief Retrieves the protocol of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The protocol of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, PROTOCOL_NONE is returned.
*/
transfer_protocol GetPacketProtocol(uint8_t *buffer);

/*
 * @brief Retrieves the parameter of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The parameter of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, PARAM_NONE is returned.
*/
transfer_param GetPacketParam(uint8_t *buffer);

/*
 * @brief Retrieves the error code of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The error code of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, ERR_INVALID is returned.
*/
error_code GetPacketError(uint8_t *buffer);

/*
 * @brief Retrieves the size of the payload of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The size of the payload of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note Payload size can be 0, as some packets do not have a payload.
*/
uint32_t GetPacketSize(uint8_t *buffer);

#endif