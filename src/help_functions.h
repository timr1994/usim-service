/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file help_functions.c
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-04-29
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef HELP_FUNCTIONS_H
#define HELP_FUNCTIONS_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
    /**
     * Writes all bytes in buf with size n into file descriptor fd. The function tries it until all bytes a writen or a error occured.
     * @param fd File descriptor in which the bytes should be writen.
     * @param buf Buffer where the bytes a read from.
     * @param n count of bytes to be writen-
     * @return -1 or 0 if an error occured or socket is closed, otherwise the writen bytes.
     */
    ssize_t full_write(int fd, void *buf, size_t n);
    /**
     * Reads from file descriptor fd until n bytes are in Buffer buf. The function tries to read from fd until n bytes a readed or a error occured.
     * @param fd File descriptor from which the bytes should be readed.
     * @param buf Buffer where the bytes a writen to.
     * @param n count of bytes to be readed.
     * @return -1 or 0 if an error occured or socket is closed, otherwise the readed bytes.
     */
    ssize_t full_read(int fd, void *buf, size_t n);
    /**
     * Prints the buffer buf in hex out.
     * @param buf Buffer where the bytes a read from.
     * @param len Length of the buffer.
     */
    void printHex(uint8_t *buf, size_t len);
    /**
     * Takes a Buffer and returns a hex represtation as String.
     * @param buf Buffer where the bytes a read from.
     * @param len Length of the buffer buf.
     * @return String with hex represantion of buf.
     */
    char *get_hex_string(uint8_t *buf, size_t len);


#ifdef __cplusplus
}
#endif

#endif /* HELP_FUNCTIONS_H */

