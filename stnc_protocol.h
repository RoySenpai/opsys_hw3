/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Protocol Header File
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

#ifndef _STNC_PROTOCOL_H
#define _STNC_PROTOCOL_H

#include "stnc_defs.h"

/*
 * @brief Returns the transfer type according to the given string.
 * @param transferType The string to check.
 * @return The transfer type according to the given string.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given string is not a valid transfer type, PROTOCOL_NONE is returned.
*/
stnc_transfer_protocol stnc_get_transfer_protocol(char *transferType);

/*
 * @brief Returns the transfer protocol according to the given string.
 * @param transferProtocol The string to check.
 * @return The transfer protocol according to the given string.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given string is not a valid transfer protocol, PROTOCOL_NONE is returned.
*/
stnc_transfer_param stnc_get_transfer_param(char *transferParam);

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
int stnc_prepare_packet(uint8_t *buffer, stnc_message_type type, stnc_transfer_protocol protocol, stnc_transfer_param param, stnc_error_code error, uint32_t size, uint8_t *data);

/*
 * @brief Sends the given packet to the given socket.
 * @param socket The socket to send the packet to.
 * @param packet The packet to send.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return number of bytes sent on success, -1 on failure.
*/
int stnc_send_tcp_data(int socket, uint8_t *packet, bool quietMode);

/*
 * @brief Receives a packet from the given socket.
 * @param socket The socket to receive the packet from.
 * @param packet The packet to receive.
 * @param quietMode Indicates whether to print activity messages or not.
 * @return number of bytes received on success, -1 on failure.
*/
int stnc_receive_tcp_data(int socket, uint8_t *packet, bool quietMode);

/*
 * @brief Retrieves the type of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The type of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, MSGT_INVALID is returned.
*/
stnc_message_type stnc_get_packet_type(uint8_t *buffer);

/*
 * @brief Retrieves the protocol of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The protocol of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, PROTOCOL_NONE is returned.
*/
stnc_transfer_protocol stnc_get_packet_protocol(uint8_t *buffer);

/*
 * @brief Retrieves the parameter of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The parameter of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, PARAM_NONE is returned.
*/
stnc_transfer_param stnc_get_packet_param(uint8_t *buffer);

/*
 * @brief Retrieves the error code of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The error code of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note If the given buffer is not a valid packet, ERR_INVALID is returned.
*/
stnc_error_code stnc_get_packet_error(uint8_t *buffer);

/*
 * @brief Retrieves the size of the payload of the given packet.
 * @param buffer The buffer to read the packet from.
 * @return The size of the payload of the given packet.
 * @note This function is used by the performance mode of the STNC program.
 * @note Payload size can be 0, as some packets do not have a payload.
*/
uint32_t stnc_get_packet_size(uint8_t *buffer);

#endif