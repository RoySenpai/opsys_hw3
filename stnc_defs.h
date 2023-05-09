/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Definitions Header File
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

#ifndef _STNC_DEFS_H
#define _STNC_DEFS_H

/*
** Include this file before including system headers.  By default, with
** C99 support from the compiler, it requests POSIX 2001 support.  With
** C89 support only, it requests POSIX 1997 support.  Override the
** default behaviour by setting either _XOPEN_SOURCE or _POSIX_C_SOURCE.
*/

/* _XOPEN_SOURCE 700 is loosely equivalent to _POSIX_C_SOURCE 200809L */
/* _XOPEN_SOURCE 600 is loosely equivalent to _POSIX_C_SOURCE 200112L */
/* _XOPEN_SOURCE 500 is loosely equivalent to _POSIX_C_SOURCE 199506L */

#if !defined(_XOPEN_SOURCE) && !defined(_POSIX_C_SOURCE)
#if __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 600   /* SUS v3, POSIX 1003.1 2004 (POSIX 2001 + Corrigenda) */
#else
#define _XOPEN_SOURCE 500   /* SUS v2, POSIX 1003.1 1997 */
#endif /* __STDC_VERSION__ */
#endif /* !_XOPEN_SOURCE && !_POSIX_C_SOURCE */


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
 * @brief Indicates whether enable quiet mode or not for the client performance mode.
 * @note The value can be either true or false.
 * @note The default value is false.
*/
#define CLIENT_QUIET_MODE false

/*
 * @brief Makes the server ignore the stop command, in performance mode.
 * @note The value can be either true or false (0 or 1).
 * @note The default value is 1 (true).
*/
#define STNC_IGNORE_STOP 1

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
 * @note This is also the chunk size (segment size) of the TCP protocol.
 * @note The default value is 65536 bytes (64KB).
*/
#define CHUNK_SIZE 65536

/*
 * @brief Defines the chunk size of the generated file, in performance mode, for the UDP protocol.
 * @note The default value is 65507 bytes.
 * @note UDP is a connectionless protocol, so the chunk size must be smaller than the MTU (Maximum Transmission Unit).
 * @note The MTU is 1500 bytes for Ethernet, 576 bytes for IPv4 and 1280 bytes for IPv6.
 * @note UDP payload can be up to 65,507 bytes.
*/
#define CHUNK_SIZE_UDP 65507

/*
 * @brief Defines the File size for the performance mode.
 * @note The default value is 100MB (104,857,600 bytes).
*/
#define FILE_SIZE 104857600

/*
 * @brief Defines the maximum size of the payload, in performance mode.
 * @note The default value is 1024 bytes (1KB).
*/
#define STNC_PROTO_MAX_SIZE 1024

/*
 * @brief Defines the timeout for the poll function, in performance mode.
 * @note The default value is 1000 milliseconds (1 second).
 * @note -1 means infinite timeout, 0 means no timeout.
 * 			Those values shouldn't be used except for debugging purposes only!
*/
#define STNC_POLL_TIMEOUT 1000

/*
 * @brief Sets the name of the UNIX socket of the server, for the performance mode.
 * @note The default value is "/tmp/stnc_uds.sock".
 * @note The name must be shorter than 108 characters.
*/
#define STNC_UNIX_NAME "/tmp/stnc_uds.sock"

/****************************/
/* Enumerations declaration */
/****************************/

/*
 * @brief Defines the type of the message for the performace test.
*/
typedef enum __attribute__((__packed__)) _STNC_MESSAGE_TYPE {
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
	MSGT_DATA
} stnc_message_type;

/*
 * @brief Defines the protocol of the transfer for the performace test.
 * @note This protocol is used to indicate the type of the transfer.
 * @note For TCP and UDP, the protocol is either PROTOCOL_IPV4 or PROTOCOL_IPV6 only.
 * @note For stream and datagram sockets, the protocol is PROTOCOL_UNIX only.
 * @note PROTOCOL_NONE is used for error.
*/
typedef enum __attribute__((__packed__)) _STNC_TRANSFER_PROTOCOL {
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
} stnc_transfer_protocol;

/*
 * @brief Defines the parameter of the transfer for the performace test.
 * @note This parameter is used to indicate the type of the transfer.
 * @note For mmap and pipe, the parameter is always PARAM_NONE.
*/
typedef enum __attribute__((__packed__)) _STNC_TRANSFER_PARAM {
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
} stnc_transfer_param;


/*
 * @brief Defines the error codes for the performace test.
 * @note This error code is used to indicate the type of the error.
 * @note The error code also provides a short description of the error, as a string payload in the message.
*/
typedef enum __attribute__((__packed__)) _STNC_ERROR_CODE {

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
	 * @brief Alloc - Error in memory allocation.
	 * @note This indicates that an error occurred in pne of the memory allocation functions (malloc, calloc, realloc).
	*/
	ERRC_ALLOC
} stnc_error_code;

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
	stnc_message_type type;

	/* 
	 * @brief The protocol of the transfer.
	 * @note This field is mandatory for all messages, and shouldn't change during the transfer.
	 * @note Field size is 1 byte.
	*/
	stnc_transfer_protocol protocol;

	/* 
	 * @brief The parameter of the transfer.
	 * @note This field is mandatory for all messages, and shouldn't change during the transfer.
	 * @note Field size is 1 byte.
	*/
	stnc_transfer_param param;

	/* 
	 * @brief The error code.
	 * @note If the error code isn't ERRC_SUCCESS, an error message will be sent as a string payload.
	 * @note Incase of an error, both parties should close the connection immediately, preventing any further communication.
	 * @note Field size is 1 byte.
	*/ 
	stnc_error_code error;

	/* 
	 * @brief The size of the payload.
	 * @note For MSGT_INIT, there isn't a payload, so this field is used to indicate the size of the file.
	 * @note For MSGT_DATA, this is the size of the payload itself.
	 * @note In all other cases, this should be 0 always, as there is no payload.
	 * @note Field size is 4 bytes.
	*/
	uint32_t size;
} stnc_packet;

#endif