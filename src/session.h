/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file session.h
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-03-04
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef SESSION_H
#define SESSION_H


#include <uiim.h>
#include <uthash.h>
#include <sys/random.h>
#include "hash_message_list_for_session.h"
#include "uiim_service_typedefs.h"
#include "session_helper.h"
#ifndef WHEELFEEDER
#include "hash_message_logger.h"
#endif
#include <errno.h>

#define HEADER_SIZE 8


#ifdef __cplusplus
extern "C" {
#endif
    void free_session(Session *ses);
    Session *find_session(uint16_t sessionId, Session **session_hashmap_head);

    void *end_session(Session *ses, Session **session_hashmap_head);

    Session *create_session(Session **session_hashmap_head, int socket, uiimconf *conf);

    void parseHeader(uint8_t *buf, Header *header);
    void parseSessionInit(uint8_t *buf, SessionInit *sesI);

    void processHashMessage(Session *ses, HASH_MESSAGE *hm, uint16_t seqNum);

    void sendAnswers(Session *ses);

    void *startThread(void *ses);



#ifdef __cplusplus
}
#endif

#endif /* SESSION_H */

