/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file distributor.c
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-24
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

/* 
 * File:   distributor.c
 * Author: tim
 * 
 * Created on 24. Juni 2020, 16:16
 */



#include "distributor.h"

PRO_RC sendAllResponses(Distribution *dis) {

    Session *ses = {0};
    int size = 0;
    ListRoot root = {.count = 0, .first = NULL, .lock = 0, .tail = NULL};
    concatAndClearAdded(&root, dis->collected);
    while (root.first != NULL) {
        RecordList *ele = root.first->value;
        HASH_FIND(hh, dis->sessionHead, &ele->vals.record->sessionId, sizeof (ele->vals.record->sessionId), ses);
        if (ses != NULL) {
            if (!ele->isMultiRecord) {
                if (ele->vals.record->sessionId == ses->sessionId) {
                    uint8_t *answer = answer_marshalling(ele->vals.record->seqNum, ele->vals.record->statusCode);
                    int rc = full_write(ses->socket, answer, SIZE_OF_ANSWER_HEADER);
                    free(answer);
                    if (rc == -1) {
                        //return ErrorWrite;
                    } else if (rc == 0) {
                        //return ConnectionClosed;
                    }
                    if (rc == SIZE_OF_ANSWER_HEADER) {
                        //
                    }
                }
            }
        }
        ListElement *toFree = root.first;
        root.first = root.first->next;
        --root.count;
        free(toFree);
    }
    return Okay;

}

void collectAllMessages(Distribution *dis) {
    WheelFeeder *ele = {0};
    WheelFeeder *tmp = {0};

    HASH_ITER(hh, dis->wfHead, ele, tmp) {
        concatAndClearAdded(dis->collected, ele->outQueue);
    }
}

void *distributerThread(void *data) {
    Distribution *dis = (Distribution*) data;
    int ntdo = 0;
    while (dis->run) {
        aquireDistributionLock(dis);
        PRO_RC rc = sendAllResponses(dis);
        releaseDistributionLock(dis);
        if (rc == NothingToProcess) {
            ntdo++;
            if (ntdo > 100) {
                ntdo = 0;
                pthread_mutex_lock(dis->sIQMutex);
                while (isEmpty(dis->collected)) {
                    pthread_cond_wait(dis->somethinInQueue, dis->sIQMutex);
                }
                pthread_mutex_unlock(dis->sIQMutex);
            }
        }
    }
}

void aquireDistributionLock(Distribution *dis) {
    while (__sync_lock_test_and_set(&(dis->lock), 1) == 1);
}

void releaseDistributionLock(Distribution *dis) {
    __sync_lock_release(&dis->lock);
}

void stopDistribution(Distribution *dis) {
    __sync_lock_test_and_set(&(dis->run), 0);
}

