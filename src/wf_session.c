/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file wf_session.c
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-10
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#include "wf_session.h"

void free_session(Session *ses) {
    free(ses->alg_ids);
    free(ses->lh);
    free(ses->producer);
}

Session *wfCreateSession(Distribution *dis, int socket, uiimconf *conf) {

    Session *ses = malloc(sizeof (Session));
    memset(ses, 0, sizeof (Session));
    ses->socket = socket;
    ses->lh = NULL;
    ses->sessionId = 0;
    Session *session_tmp = NULL;
    do {
        uint16_t newSessionId = 0;
        getrandom(&newSessionId, sizeof (newSessionId), 0);
        HASH_FIND(hh, dis->sessionHead, &newSessionId, sizeof (newSessionId), session_tmp);
        if (session_tmp == NULL) {
            ses->sessionId = newSessionId;
            HASH_ADD(hh, dis->sessionHead, sessionId, sizeof (ses->sessionId), ses);
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
    ses->wf = getWF(dis, conf, ses->pcr);
    pthread_rwlock_wrlock(ses->wf->userRWLock);
    ses->wf->user++;
    pthread_rwlock_unlock(ses->wf->userRWLock);
    ses->closed = false;
    return ses;
}

PRO_RC process_new_messages(Session *session) {
    uint8_t header[SIZE_OF_MESSAGE_HEADER] = {0};
    Header head = {0};
    //memset(&head, 0, sizeof (Header));
    int rrc = full_read(session->socket, header, sizeof (header));
    if (rrc == -1) {
        return ErrorRead;

    } else if (rrc == 0) {
        session->closed = true;
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
        session->closed = true;
        return ConnectionClosed;
    }
    uint8_t *hm_buf = malloc(head.len);
    rrc = full_read(session->socket, hm_buf, head.len);
    if (rrc == -1) {
        return ErrorRead;
    }
    if (rrc == head.len) {

        HASH_MESSAGE *hm = unmarshalling(hm_buf, head.len);
        Record *record = malloc(sizeof (Record));
        memset(record, 0, sizeof (Record));
        record->flags = session->flags;
        record->hm = hm;
        record->producer = session->producer;
        record->seqNum = head.seqNum;
        record->sessionId = session->sessionId;
        RecordList *rl = malloc(sizeof (RecordList));
        rl->index = 0;
        rl->isMultiRecord = false;
        rl->vals.record = record;
        wfPut(session->wf, rl);
        free(hm_buf);
    }
    return Okay;
}

void *processNewMessagesT(void *data) {
    Session *session = (Session*) data;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    struct sigaction new_action;
    memset(&new_action, 0, sizeof (struct sigaction));
    sigemptyset(&new_action.sa_mask);
    new_action.sa_handler = sigusr2_handler;
    sigaction(SIGUSR2, &new_action, NULL);
    while (1) {
        PRO_RC rc = process_new_messages(session);
        if (rc != Okay) {
            break;
        }
    }
}

/*PRO_RC process_out_queue(Session *ses) {
    return wf_send_for_session(ses);
}

void *process_out_queue_t(void *data) {
    Session *ses = (Session*) data;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    struct sigaction new_action;
    memset(&new_action, 0, sizeof (struct sigaction));
    sigemptyset(&new_action.sa_mask);
    new_action.sa_handler = sigusr2_handler;
    sigaction(SIGUSR2, &new_action, NULL);
    while (1) {
        PRO_RC rc = process_out_queue(ses);
        if (rc != Okay) {
            break;
        }
    }
}*/
