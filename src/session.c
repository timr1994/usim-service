/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file session.c
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

#include <unistd.h>
#include <hash_message_cbor.h>
#include <utlist.h>
#include <signal.h>

#include "session.h"
#include "uiimconf.h"
#include "help_functions.h"
#include "hash_message_list_for_session.h"


void free_session(Session *ses) {
    HashMessageLogger *logger = getLoggerForPCRToFree(ses->pcr);
    freeLogger(logger);
    HM_List *el, *tmp = NULL;

    LL_FOREACH_SAFE(ses->lh, el, tmp) {
        LL_DELETE(ses->lh, el);
        freeHML(el);
    }
    free(ses->producer);

}



Session *create_session(Session **session_hashmap_head, int socket, uiimconf *conf) {

    Session *ses = malloc(sizeof (Session));
    memset(ses, 0, sizeof (Session));
    ses->socket = socket;
    ses->lh = NULL;
    ses->sessionId = 0;
    Session *session_tmp = NULL;
    do {
        uint16_t newSessionId = 0;
        getrandom(&newSessionId, sizeof (newSessionId), 0);
        HASH_FIND_INT(*session_hashmap_head, &newSessionId, session_tmp);
        if (session_tmp == NULL) {
            ses->sessionId = newSessionId;
            HASH_ADD_INT(*session_hashmap_head, sessionId, ses);
        }

    } while (session_tmp != NULL);
    PRO_RC rc = sesInit(ses);
    if (rc != SessionInitated) {
        free(ses);
        return NULL;
    }

    ses->alg_ids_len = conf->alg_ids_len;
    ses->alg_ids = calloc(conf->alg_ids_len, sizeof (TPM2_ALG_ID));
    for (uint8_t i = 0; i < ses->alg_ids_len; i++) {
        ses->alg_ids[i] = conf->alg_ids[i];
    }
    ses->logger = getLoggerForPCR(conf, ses->pcr);
    return ses;
}

PRO_RC processing(Session *session) {
    uint8_t header[SIZE_OF_MESSAGE_HEADER] = {0};
    Header head = {0};
    //memset(&head, 0, sizeof (Header));
    int rrc = full_read(session->socket, header, sizeof (header));
    if (rrc == -1) {
        if (errno == EWOULDBLOCK) {
            return InvalidMessageReceived;
        } else {
            return ErrorRead;
        }
    } else if (rrc == 0) {
        return ConnectionClosed;
    }
    if (rrc == SIZE_OF_MESSAGE_HEADER) {
        parseHeader(header, &head);
    }
    if (head.sessionId != session->sessionId) {
        return InvalidMessageReceived;
    } else if (head.sessionId == session->sessionId && head.seqNum == 0 && head.len == 0) {
        //SessionEnd
        close(session->socket);
        return ConnectionClosed;
    }
    uint8_t *hm_buf = malloc(head.len);
    rrc = full_read(session->socket, hm_buf, head.len);
    if (rrc == -1) {
        if (errno == EWOULDBLOCK) {
            return InvalidMessageReceived;
        } else {
            return ErrorRead;
        }
    }
    if (rrc == head.len) {

        HASH_MESSAGE *hm = unmarshalling(hm_buf, head.len);
        processHashMessage(session, hm, head.seqNum);
        free(hm_buf);
    }
    return Okay;


}



void processHashMessage(Session *ses, HASH_MESSAGE *hm, uint16_t seqNum) {
    uint8_t flags = ses->flags;
    HM_List *hml = malloc(sizeof (HM_List));
    memset(hml, 0, sizeof (HM_List));
    hml->hm = hm;
    hml->seqNum = seqNum;
    hml->rc = Nothing;
    hml->answered = false;
    //printf("Session :%d, SeqNum: %d\n", ses->sessionId, hml->seqNum);
    if (flags & DO_NOT_HANDLE_DUPLICATES) {
        if (flags & LOG_MULTIPLE_RECORDS_AS_ONE) {
            LL_APPEND(ses->lh, hml);
            logMultipleHashMessages(ses->logger, ses->producer, hm, &hml->rc);
        } else {
            LL_APPEND(ses->lh, hml);
            hml->rc = logHashMessage(ses->logger, ses->producer, hm);
        }
    } else {
        IN_RC inrc = hashMessageExists(ses->logger, hm);
        if (inrc == Nothing) {
            if (flags & LOG_MULTIPLE_RECORDS_AS_ONE) {
                LL_APPEND(ses->lh, hml);
                logMultipleHashMessages(ses->logger, ses->producer, hm, &hml->rc);
            } else {
                LL_APPEND(ses->lh, hml);
                hml->rc = logHashMessage(ses->logger, ses->producer, hm);
            }
        } else {

            LL_APPEND(ses->lh, hml);
            hml->rc = inrc;

        }
    }
}

/**
 * 
 * @param ses
 */
void sendAnswers(Session *ses) {
    HM_List *elt;

    LL_FOREACH(ses->lh, elt) {

        if (!elt->answered) {
            //printf("Session :%d, SeqNum: %d, Answered: %d, RC: %d\n", ses->sessionId, elt->seqNum, elt->answered, elt->rc);
            if (elt->rc != Nothing) {
                uint8_t *answer = answer_marshalling(elt->seqNum, elt->rc);
                int rc = full_write(ses->socket, answer, SIZE_OF_ANSWER_HEADER);
                free(answer);
                if (rc == -1) {
                    if (errno == EWOULDBLOCK) {
                        break;
                    } else {
                        printf("Konnte nicht senden\n");
                    }
                } else if (rc == 0) {
                    printf("Konnte nicht senden\n");
                }
                if (rc == SIZE_OF_ANSWER_HEADER) {

                    elt->answered = true;
                }
            }
        }
    }
}

void sigusr2_handler(int signo) {
    if (signo == SIGUSR2) {

        pthread_exit(NULL);
    }
}

void *startThread(void *ses) {
    Session *session = (Session *) ses;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    struct sigaction new_action;
    memset(&new_action, 0, sizeof (struct sigaction));
    sigemptyset(&new_action.sa_mask);
    new_action.sa_handler = sigusr2_handler;
    sigaction(SIGUSR2, &new_action, NULL);
    while (true) {
        PRO_RC rc = processing(session);
        if (rc == InvalidMessageReceived) {
            processQueue(session->logger, true);
            sendAnswers(session);
        }
        if (rc == ErrorRead || rc == ErrorWrite || rc == ConnectionClosed) {
            break;
        }
    }
}