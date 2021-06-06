/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file session_helper.h
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-11
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

/* 
 * File:   session_helper.h
 * Author: tim
 *
 * Created on 11. Juni 2020, 10:17
 */

#ifndef SESSION_HELPER_H
#define SESSION_HELPER_H
#include <uiim.h>
#include "uiim_service_typedefs.h"

#ifdef __cplusplus
extern "C" {
#endif
    /**
     * Parses the buffer buf into the store header.
     * @param buf Buffer with the size of 8 bytes.
     * @param header Header where the parsed data are stored.
     */
    void parseHeader(uint8_t *buf, Header *header);
    /**
     * Parses the buffer buf into the store sesI.
     * @param buf Buffer with at least the size of 8 byte.
     * @param sesI SessionInit here the parsed data are stored.
     */
    void parseSessionInit(uint8_t *buf, SessionInit *sesI);
    /**
     * S
     * @param session
     * @return 
     */
    PRO_RC sesInit(Session *session);
#ifdef __cplusplus
}
#endif
#endif /* SESSION_HELPER_H */
