/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file session_helper.c
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-11
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#include "session_helper.h"

void parseHeader(uint8_t *buf, Header *header) {

    memcpy(&header->sessionId, buf, sizeof (header->sessionId));
    header->sessionId = ntohs(header->sessionId);
    memcpy(&header->seqNum, buf + 2, sizeof (header->seqNum));
    header->seqNum = ntohs(header->seqNum);
    memcpy(&header->len, buf + 4, sizeof (header->len));
    header->len = ntohl(header->len);
}
void parseSessionInit(uint8_t *buf, SessionInit *sesI) {

    memcpy(&sesI->pcr, buf, sizeof (sesI->pcr));
    memcpy(&sesI->flags, buf + 3, sizeof (sesI->flags));
    memcpy(&sesI->len_producer, buf + 4, sizeof (sesI->len_producer));
    sesI->len_producer = ntohl(sesI->len_producer);
    sesI->producer = malloc(sesI->len_producer + 1);
    memset(sesI->producer, '\0', sesI->len_producer + 1);
    strncpy(sesI->producer, buf + 8, sesI->len_producer);
}
PRO_RC sesInit(Session *session) {
    uint8_t header[SIZE_OF_MESSAGE_HEADER];
    Header head;
    SessionInit sesI;
    int readedHeader = full_read(session->socket, header, sizeof (header));
    if (readedHeader == SIZE_OF_MESSAGE_HEADER) {
        parseHeader(header, &head);
        if (head.sessionId == 0) {
            //SESSION INIT
            uint8_t *sesIBuf = malloc(head.len);
            int readedSesI = full_read(session->socket, sesIBuf, head.len);
            if (readedSesI == -1) {
                free(sesIBuf);
                return ErrorRead;
            } else if (readedSesI != head.len) {
                free(sesIBuf);
                return InvalidMessageReceived;
            } else {
                parseSessionInit(sesIBuf, &sesI);
                session->pcr = sesI.pcr;
                session->producer = malloc(sesI.len_producer + 1);
                memset(session->producer, '\0', sesI.len_producer + 1);
                strncpy(session->producer, sesI.producer, sesI.len_producer);
                session->flags = sesI.flags;
                free(sesI.producer);
                free(sesIBuf);
                uint8_t *reBuf = answer_marshalling(session->sessionId, SessionStart);
                int rc = full_write(session->socket, reBuf, SIZE_OF_ANSWER_HEADER);
                if (rc != SIZE_OF_ANSWER_HEADER) {
                    free(reBuf);
                    return SessionInitatedFail;
                }
                free(reBuf);
                return SessionInitated;
            }
        } else {
            return SessionInitatedFail;
        }
    } else if (readedHeader == -1) {
        return ErrorRead;
    } else {
        return InvalidMessageReceived;
    }
}