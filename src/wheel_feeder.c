/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file wheel_feeder.c
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-10
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */



#include "wheel_feeder.h"

void sigusr2_handler(int signo) {
    if (signo == SIGUSR2) {
        pthread_exit(NULL);
    }
}

/**
 * Parse the log file to 
 * @param wf
 */
void parse_log_file(WheelFeeder *wf) {
    uint64_t size = 0;
    uint8_t typ = 0;
    ssize_t readed = 0;
    do {
        readed = read(wf->logfile, &size, sizeof (size));
        BREAK_NES(readed);
        readed = read(wf->logfile, &typ, sizeof (typ));
        BREAK_NES(readed);
        uint8_t *buf = malloc(size);
        readed = read(wf->logfile, buf, size);
        BREAK_NES(readed);
        if (typ == RTM) {
            MultiRecord *mrecord = multiRecordUnmarshalling(buf, size);
            addMultiRecord(wf, mrecord, false);
        } else if (typ == RTO) {
            Record *record = recordUnmarshalling(buf, size);
            addRecord(wf, record, false);
        }
        free(buf);
    } while (readed > 0);


}

WheelFeeder *getWF(Distribution *dis, uiimconf *conf, uint8_t pcr) {

    WheelFeeder *new_wf = NULL;
    int key = pcr;
    HASH_FIND_INT(dis->wfHead, &key, new_wf);
    if (new_wf == NULL && conf != NULL) {
        new_wf = malloc(sizeof (WheelFeeder));
        memset(new_wf, 0, sizeof (WheelFeeder));
        wfInit(new_wf, pcr, conf->LOG_OUTPUT_PATH, conf->alg_ids, conf->alg_ids_len, dis);
        new_wf->key = key;
        pthread_create(&new_wf->threadID, 0, wfProcessT, new_wf);
        HASH_ADD_INT(dis->wfHead, key, new_wf);
        return new_wf;
    }
    return new_wf;

}

IN_RC wfInit(WheelFeeder *wf, uint8_t pcr, const char *path, TPM2_ALG_ID *alg_ids, uint8_t alg_ids_len, Distribution *dis) {
    if (wf != NULL) {
        wf->mesIn = malloc(sizeof (pthread_cond_t));
        memset(wf->mesIn, 0, sizeof (pthread_cond_t));
        wf->somethinInQueue = malloc(sizeof (pthread_cond_t));
        memset(wf->somethinInQueue, 0, sizeof (pthread_cond_t));
        wf->userRWLock = malloc(sizeof (pthread_rwlock_t));
        memset(wf->userRWLock, 0, sizeof (pthread_rwlock_t));
        wf->inQueue = listRootInit();
        wf->outQueue = dis->collected;
        wf->processQueue = listRootInit();
        wf->re_list = listRootInit();
        wf->alg_ids = malloc(alg_ids_len * sizeof (TPM2_ALG_ID));
        for (uint8_t i = 0; i < alg_ids_len; i++) {
            wf->alg_ids[i] = alg_ids[i];
        }
        wf->alg_ids_len = alg_ids_len;
        wf->pcr = pcr;
        char *full_file_path = malloc(strlen(path) + strlen(LOG_FILE_NAME) + 1);
        sprintf(full_file_path, "%s/pcr%0d.log", path, pcr);
        wf->logfile = open(full_file_path, O_APPEND | O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP);
        if (wf->logfile == -1) {
            printf("Can not open path: %s\n", full_file_path);
            return LoggerInitFailed;
        }
        parse_log_file(wf);
        free(full_file_path);
        wf->mesInMutex = malloc(sizeof (pthread_mutex_t));
        pthread_mutex_init(wf->mesInMutex, 0);
        pthread_cond_init(wf->mesIn, 0);
        pthread_cond_init(wf->somethinInQueue, 0);
        pthread_rwlock_init(wf->userRWLock, 0);
        wf->user = 0;
    }
}

void wfPut(WheelFeeder *wf, RecordList *element) {
    listAdd(wf->inQueue, element);
    pthread_cond_signal(wf->mesIn);
}

void wfRotate(WheelFeeder *wf) {
    concatAndClearAdded(wf->outQueue, wf->processQueue);
    concatAndClearAdded(wf->processQueue, wf->inQueue);
    if (!isEmpty(wf->outQueue)) {
        pthread_cond_signal(wf->somethinInQueue);
    }
}

RecordList *wfTake(WheelFeeder *wf) {
    return get(wf->outQueue, 0);
}

/*RecordList *wf_take_all(WheelFeeder *wf) {
    // No lock required Function call is atomic.//ONLY GCC//
    return __sync_lock_test_and_set(&wf->outQueue, NULL);
}*/

/**
 * Checks whether a given HASH_MESSAGE already exists or not, and if it already exists, whether the hash values have changed.
 * @param wf The WheelFeeder with the map that should be used.
 * @param hm The HASH_MESSAGE that should be checked.
 * @return Returns "Nothing" if the HASH_MESSAGE does not exist in the map. Returns "AlreadyInsert" if the HASH_MESSAGE is already inserted and the hash values are equal, otherwise it returns "Collision".
 */
IN_RC hash_message_exists(WheelFeeder *wf, HASH_MESSAGE *hm) {
    HASH_MESSAGE *cmp = NULL;
    HASH_FIND_STR(wf->hm_map, hm->event_id, cmp);
    if (cmp == NULL) {
        return Nothing;
    } else {
        int collsions = 0;
        for (uint8_t i = 0; i < cmp->h_payload_size; i++) {
            for (uint8_t j = 0; j < hm->h_payload_size; j++) {
                if (cmp->h_payload[i].alg_name == hm->h_payload[j].alg_name) {
                    int rc = memcmp(cmp->h_payload[i].hash_data, hm->h_payload[j].hash_data, get_hash_data_size_by_alg_name(cmp->h_payload[i].alg_name));
                    if (rc != 0) {
                        collsions++;
                    }
                }
            }
        }
        if (collsions > 0) {
            return Collision;
        } else {
            return AlreadyInsert;
        }
    }
}

/**
 * 
 * @param wf
 * @param algId
 * @return 
 */
bool isSelected(WheelFeeder *wf, TPM2_ALG_ID algId) {
    for (u_int8_t i = 0; i < wf->alg_ids_len; i++) {
        if (wf->alg_ids[i] == algId) {
            return true;
        }
    }
    return false;
}

/**
 * Calculates the hashes for the MultiRecord with the selected algorithms from the WheelFeeder.
 * @param wf WheelFeeder with the selected algorithms.
 * @param mrecord MultiRecord for which the hashes are to be calculated.
 */
void set_all_hash_multi_record(WheelFeeder *wf, MultiRecord *mrecord) {
    if (isSelected(wf, TPM2_ALG_SHA1)) {
        setSHA1HashMultiRecord(mrecord);
    }
    if (isSelected(wf, TPM2_ALG_SHA256)) {
        setSHA256HashMultiRecord(mrecord);
    }

    if (isSelected(wf, TPM2_ALG_SHA384)) {
        setSHA384HashMultiRecord(mrecord);
    }

    if (isSelected(wf, TPM2_ALG_SHA512)) {
        setSHA512HashMultiRecord(mrecord);
    }

}

/**
 * Processes all entries in the processing queue.
 * @param wf The WheelFeeder which processing queue should be used.
 * @return Okay, if there's anything to process, otherwise NothingToProcess.
 */
PRO_RC wf_process(WheelFeeder *wf) {
    RecordList *ele = NULL;
    aquireLock(wf->processQueue);
    if (isEmpty(wf->processQueue)) {
        releaseLock(wf->processQueue);
        wfRotate(wf);
        return NothingToProcess;

    }
    //Ist nur ein Thread nicht wirklich nötig;
    if (wf->processQueue->first->next == NULL) {
        ele = wf->processQueue->first->value;
        ele->vals.record->statusCode = addRecord(wf, ele->vals.record, true);
    } else {
        MultiRecord * mrec = malloc(sizeof (MultiRecord));
        memset(mrec, 0, sizeof (MultiRecord));
        mrec->count = 0;
        mrec->records = realloc(mrec->records, MTSLSize(wf->processQueue) * sizeof (Record*));
        mrec->multihash = NULL;
        mrec->multihash_size = 0;
        for (ListElement *elel = wf->processQueue->first; elel != NULL; elel = elel->next) {
            RecordList *ele = elel->value;
            if (ele->vals.record->flags && DO_NOT_HANDLE_DUPLICATES) {
                mrec->records[mrec->count++] = ele->vals.record;
            } else {
                ele->vals.record->statusCode = hash_message_exists(wf, ele->vals.record->hm);
                if (ele->vals.record->statusCode == Nothing) {
                    mrec->records[mrec->count++] = ele->vals.record;
                }
            }
        }
        mrec->records = realloc(mrec->records, (mrec->count) * sizeof (Record*));
        set_all_hash_multi_record(wf, mrec);
        writeMultiRecord(wf->logfile, mrec);
        IN_RC rc = addMultiRecord(wf, mrec, true);
        for (int i = 0; i < mrec->count; i++) {
            mrec->records[i]->statusCode = rc;
        }

    }
    releaseLock(wf->processQueue);
    wfRotate(wf);
    return Okay;


}

void *wfProcessT(void *data) {
    WheelFeeder *wf = (WheelFeeder*) data;
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
    int ntpc = 0;
    while (1) {
        PRO_RC rc = wf_process(wf);
        if (rc == NothingToProcess) {
            ntpc++;
            if (ntpc == 100) {
                ntpc = 0;
                while (isEmpty(wf->inQueue)) {
                    pthread_mutex_lock(wf->mesInMutex);
                    pthread_cond_wait(wf->mesIn, wf->mesInMutex);
                    pthread_mutex_unlock(wf->mesInMutex);
                }
            }
        } else if (rc != Okay) {
            break;
        }

    }
    return NULL;
}

void freeWF(WheelFeeder *wf) {
    HASH_MESSAGE *act, *tmp;

    HASH_ITER(hh, wf->hm_map, act, tmp) {
        HASH_DEL(wf->hm_map, act);
    }
    //free(wf->hm_map);
    int size = 0;
    RecordList **arr = toArrayAndRemove(wf->re_list, &size);
    for (int i = 0; i < size - 1; i++) {
        freeRecordList(arr[i]);
    }
    //free(arr);
    size = 0;
    arr = toArrayAndRemove(wf->inQueue, &size);
    for (int i = 0; i < size; i++) {
        freeRecordList(arr[i]);
    }
    //free(arr);
    size = 0;
    arr = toArrayAndRemove(wf->processQueue, &size);
    for (int i = 0; i < size; i++) {
        freeRecordList(arr[i]);
    }
    //free(arr);
    free(wf->alg_ids);
    free(wf->mesIn);
    free(wf->inQueue);
    free(wf->mesInMutex);
    //free(wf->outQueue);
    free(wf->processQueue);
    free(wf->re_list);
    free(wf->somethinInQueue);
    free(wf->userRWLock);
    free(wf);
}

/*PRO_RC wf_send_for_session(Session * session) {
    WheelFeeder *wf = session->wf;
    if (session->closed) {
        return ConnectionClosed;
    }
    pthread_mutex_lock(wf->outMutex);
    RecordList *tmp = NULL;
    RecordList *elt = NULL;

    DL_FOREACH_SAFE(wf->outQueue, elt, tmp) {
        if (!elt->isMultiRecord) {
            if (elt->vals.record->sessionId == session->sessionId) {
                uint8_t *answer = answer_marshalling(elt->vals.record->seqNum, elt->vals.record->statusCode);
                int rc = full_write(session->socket, answer, SIZE_OF_ANSWER_HEADER);
                free(answer);
                if (rc == -1) {
                    pthread_mutex_unlock(wf->outMutex);
                    return ErrorWrite;
                } else if (rc == 0) {
                    pthread_mutex_unlock(wf->outMutex);
                    return ConnectionClosed;
                }
                if (rc == SIZE_OF_ANSWER_HEADER) {
                    DL_DELETE(wf->outQueue, elt);
                }
            }
        }
    }
    pthread_mutex_unlock(wf->outMutex);
    return Okay;
}*/


