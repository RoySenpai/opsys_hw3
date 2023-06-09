/*
 *  Operation Systems (OSs) Course Assignment 3
 *  Student Network Communication (STNC) Utilities Header File
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

#ifndef _STNC_UTILS_H
#define _STNC_UTILS_H

#include "stnc_defs.h"

/*
 * @brief Prints the usage of the STNC program (General usage).
 * @param programName The name of the program.
 * @param mode Mode to print (0 - General, 1 - Client, 2 - Server)
 * @return void (no return value).
 * @note This function is used by the main function of the STNC program.
*/
void stnc_print_usage(char *programName, uint8_t mode);

/*
 * @brief Prints the license of the STNC program.
 * @return void (no return value).
 * @note This function is used by the main function of the STNC program.
*/
void stnc_print_license();

/*
 * @brief Generates random data for the performace test, according to the given size.
 * @param size The size of the data buffer.
 * @param quietMode If set to 1, the function will not print any messages.
 * @return A pointer to the generated data, or NULL on failure.
 * @note The data is generated using the rand() function.
 * @note The data is generated in blocks of 64KB.
 * @note If the size is not a multiple of 64KB, the last block will be smaller.
 * @note The caller is responsible for freeing the allocated memory.
*/
uint8_t* util_generate_random_data(uint32_t size, bool quietMode);

/*
 * @brief Prints the given packet data.
 * @param packet The packet to print.
 * @return 0 on success, 1 on failure.
 * @note This function is used by the performance mode of the STNC program.
*/
int32_t stnc_print_packet_data(stnc_packet *packet);

/*
 * @brief Prints the payload of the given packet.
 * @param packet The packet to print.
 * @return 0 on success, 1 on failure.
 * @note This function is used by the performance mode of the STNC program.
*/
int32_t stnc_print_packet_payload(stnc_packet *packet);

/*
 * @brief Calculates the MD5 hash of the given data.
 * @param data The data to calculate the checksum for.
 * @param size The size of the data.
 * @return The checksum of the given data, as a allocated string, 
 * 			or NULL on failure.
 * @note The returned string must be freed by the caller.
*/
char* util_md5_checksum(uint8_t *data, uint32_t size);

/*
 * @brief Validates the given data.
 * @param data The data to validate.
 * @param size The size of the data.
 * @return True if the data is valid, false otherwise.
 * @note This function is used by the performance mode of the STNC program.
 * @note The data is valid if it contains the data signature.
*/
bool util_is_valid_data(uint8_t *data, uint32_t size);


#endif