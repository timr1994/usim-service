/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file hash_message_logger.c
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 2020-04-10
 *  
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 *  Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */
#include "hash_message_logger.h"



#define LOG_FILE_NAME "/pcr000.log"

#define BREAK_NES(rc) if(rc<=0){break;}

void parse_log_file(HashMessageLogger *logger) {
    uint64_t size = 0;
    uint8_t typ = 0;
    ssize_t readed = 0;
    do {
        readed = read(logger->fd, &size, sizeof (size));
        BREAK_NES(readed);
        readed = read(logger->fd, &typ, sizeof (typ));
        BREAK_NES(readed);
        uint8_t *buf = malloc(size);
        readed = read(logger->fd, buf, size);
        BREAK_NES(readed);
        if (typ == RTM) {
            MultiRecord *mrecord = multiRecordUnmarshalling(buf, size);
            addMultiRecord(logger, mrecord, false);
        } else if (typ == RTO) {
            Record *record = recordUnmarshalling(buf, size);
            addRecord(logger, record, false);
        }
        free(buf);
    } while (readed > 0);


}

IN_RC loggerInit(HashMessageLogger *logger, uint8_t pcr, const char *path, TPM2_ALG_ID *alg_ids, uint8_t alg_ids_len) {
    logger->alg_ids = malloc(alg_ids_len * sizeof (TPM2_ALG_ID));
    for (uint8_t i = 0; i < alg_ids_len; i++) {
        logger->alg_ids[i] = alg_ids[i];
    }
    logger->alg_ids_len = alg_ids_len;
    logger->counter = 0;
    logger->pcr = pcr;
    logger->hm_map = NULL;
    logger->re_list = NULL;
    char *full_file_path = malloc(strlen(path) + strlen(LOG_FILE_NAME) + 1);
    sprintf(full_file_path, "%s/pcr%0d.log", path, pcr);
    logger->fd = open(full_file_path, O_APPEND | O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP);
    if (logger->fd == -1) {
        printf("Can not open path: %s\n", full_file_path);
        return LoggerInitFailed;
    }
    logger->mutex = malloc(sizeof (pthread_mutex_t));
    int rc = pthread_mutex_init(logger->mutex, 0);
    if (rc != 0) {
        return LoggerInitFailed;
    }
    parse_log_file(logger);
    logger->que = StsQueue.create();
    free(full_file_path);
}

bool isSelected(HashMessageLogger *logger, TPM2_ALG_ID algId) {
    for (u_int8_t i = 0; i < logger->alg_ids_len; i++) {
        if (logger->alg_ids[i] == algId) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Extend a TPM PCR on base of a HASH_MESSAGE
 * 
 * @param hm HASH_MESSAGE to used for extend
 * @return 1 on error, 0 on sucess
 */
TSS2_RC pcrExtend(HashMessageLogger *logger, RecordList *rl) {
    TSS2_RC tss_rc = 0;
    TPML_DIGEST_VALUES dig;
    int digC = 0;
    hash_payload *hp = NULL;
    uint8_t size = 0;
    if (rl->isMultiRecord) {
        hp = rl->vals.multiRecord->multihash;
        size = rl->vals.multiRecord->multihash_size;
    } else {
        hp = rl->vals.record->hm->h_payload;
        size = rl->vals.record->hm->h_payload_size;
    }
    for (uint8_t i = 0; i < size; i++) {
        dig.digests[i].hashAlg = hp[i].alg_name;
        switch (hp[i].alg_name) {
            case TPM2_ALG_SHA256:
                if (isSelected(logger, TPM2_ALG_SHA256)) {
                    memcpy(dig.digests[i - digC].digest.sha256, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SHA1:
                if (isSelected(logger, TPM2_ALG_SHA1)) {
                    memcpy(dig.digests[i - digC].digest.sha1, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SHA384:
                if (isSelected(logger, TPM2_ALG_SHA384)) {
                    memcpy(dig.digests[i - digC].digest.sha384, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SHA512:
                if (isSelected(logger, TPM2_ALG_SHA512)) {
                    memcpy(dig.digests[i - digC].digest.sha512, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SM3_256:
                if (isSelected(logger, TPM2_ALG_SM3_256)) {
                    memcpy(dig.digests[i - digC].digest.sm3_256, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            default:
                break;
        }


    }
    dig.count = size - digC; //max size seems to be 16 elements

    ESYS_CONTEXT *esys_ctx = NULL;
    if ((tss_rc = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS) {
        printf("%s", "Error init");
        return tss_rc;
    }
    if ((tss_rc = tpm2_pcr_extend(esys_ctx, logger->pcr, &dig)) != TSS2_RC_SUCCESS) {
        printf("%s", "Error ext");
        Esys_Finalize(&esys_ctx);
        return tss_rc;
    }
    Esys_Finalize(&esys_ctx);

    return TSS2_RC_SUCCESS;
}

IN_RC logHashMessage(HashMessageLogger *logger, const char *producer, HASH_MESSAGE *hm) {
    IN_RC rc = Nothing;
    ssize_t rcc = 0;
    Record *record = malloc(sizeof (Record));
    record->hm = hm;
    record->producer = strdup(producer);
    record->rc = NULL;
    uint64_t size = getSizeOfRecord(record);
    pthread_mutex_lock(logger->mutex);
    rcc = full_write(logger->fd, &size, sizeof (size));
    if (rcc <= 0) {
        pthread_mutex_unlock(logger->mutex);
        free(record);
        return NoRessources;
    }
    //WRITE TYP
    rcc = full_write(logger->fd, (uint8_t *) & RTO, sizeof (RTO));
    if (rcc <= 0) {
        pthread_mutex_unlock(logger->mutex);
        free(record);
        return NoRessources;
    }
    uint8_t *buf = recordMarshalling(record);
    rcc = full_write(logger->fd, buf, size);
    if (rcc <= 0) {
        pthread_mutex_unlock(logger->mutex);
        free(buf);
        free(record);
        return NoRessources;
    }
    free(buf);
    logger->counter++;
    rc = addRecord(logger, record, true);
    if (hashMessageExists(logger, hm) == Nothing) {
        HASH_ADD_STR(logger->hm_map, event_id, hm);
    }
    pthread_mutex_unlock(logger->mutex);
    return rc;
}

void logMultipleHashMessages(HashMessageLogger *logger, const char *producer, HASH_MESSAGE *hm, volatile IN_RC *rc) {
    static int loCounter = 0;
    pthread_mutex_lock(logger->mutex);
    Record *record = malloc(sizeof (Record));
    record->hm = hm;
    record->producer = strdup(producer);
    record->rc = rc;
    StsQueue.push(logger->que, record);
    logger->counter++;
    loCounter++;
    if (hashMessageExists(logger, hm) == Nothing) {
        HASH_ADD_STR(logger->hm_map, event_id, hm);
    }
    pthread_mutex_unlock(logger->mutex);
    if (loCounter >= MAX_SIZE_MULTI_RECORD) {
        processQueue(logger, false);
        loCounter = 0;
    }

}

void processQueue(HashMessageLogger *logger, bool endExpected) {
    pthread_mutex_lock(logger->mutex);
    MultiRecord *mrec = malloc(sizeof (MultiRecord));
    memset(mrec, 0, sizeof (MultiRecord));
    mrec->count = 0;
    mrec->records = calloc(MAX_SIZE_MULTI_RECORD, sizeof (Record));
    mrec->multihash = NULL;
    mrec->multihash_size = 0;
    Record *record = StsQueue.pop(logger->que);
    while (record != NULL) {
        mrec->records[mrec->count++] = record;
        if (mrec->count == MAX_SIZE_MULTI_RECORD) {
            setAllHashMultiRecord(logger, mrec);
            writeMultiRecord(logger->fd, mrec);
            addMultiRecord(logger, mrec, true);

            mrec = malloc(sizeof (MultiRecord));
            mrec->count = 0;
            mrec->records = calloc(MAX_SIZE_MULTI_RECORD, sizeof (Record));
            mrec->multihash = NULL;
            mrec->multihash_size = 0;
        }
        record = StsQueue.pop(logger->que);
    }
    if (mrec->count != 0 && endExpected) {
        setAllHashMultiRecord(logger, mrec);
        writeMultiRecord(logger->fd, mrec);
        addMultiRecord(logger, mrec, true);
    } else if (mrec->count != 0) {
        while (mrec->count != 0) {
            StsQueue.push(logger->que, mrec->records[--mrec->count]);
        }
        free(mrec->records);
        free(mrec);
    } else {
        free(mrec->records);
        free(mrec);
    }

    pthread_mutex_unlock(logger->mutex);
}

IN_RC hashMessageExists(HashMessageLogger *logger, HASH_MESSAGE *hm) {
    HASH_MESSAGE *cmp = NULL;
    HASH_FIND_STR(logger->hm_map, hm->event_id, cmp);
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
        if (collsions == 0) {
            return Collision;
        } else {
            return AlreadyInsert;
        }
    }
}

void setAllHashMultiRecord(HashMessageLogger *logger, MultiRecord *mrecord) {
    if (isSelected(logger, TPM2_ALG_SHA1)) {
        setSHA1HashMultiRecord(mrecord);
    }
    if (isSelected(logger, TPM2_ALG_SHA256)) {
        setSHA256HashMultiRecord(mrecord);
    }

    if (isSelected(logger, TPM2_ALG_SHA384)) {
        setSHA384HashMultiRecord(mrecord);
    }

    if (isSelected(logger, TPM2_ALG_SHA512)) {

        setSHA512HashMultiRecord(mrecord);
    }

}

HashMessageLogger *getLoggerForPCR_(uiimconf *conf, uint8_t pcr, bool to_free) {
    HashMessageLogger *hmloggger = NULL;
    int key = pcr;
    static HashMessageLogger *logger_head = NULL;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);
    HASH_FIND_INT(logger_head, &key, hmloggger);
    if (hmloggger == NULL && !to_free && conf != NULL) {
        hmloggger = malloc(sizeof (HashMessageLogger));
        memset(hmloggger, 0, sizeof (HashMessageLogger));
        loggerInit(hmloggger, pcr, conf->LOG_OUTPUT_PATH, conf->alg_ids, conf->alg_ids_len);
        hmloggger->key = key;
        HASH_ADD_INT(logger_head, key, hmloggger);
        pthread_mutex_unlock(&mutex);
        return hmloggger;
    } else if (hmloggger != NULL && to_free) {
        HASH_DEL(logger_head, hmloggger);
    }
    pthread_mutex_unlock(&mutex);

    return hmloggger;
}

HashMessageLogger *getLoggerForPCR(uiimconf *conf, uint8_t pcr) {

    return getLoggerForPCR_(conf, pcr, false);
}

HashMessageLogger *getLoggerForPCRToFree(uint8_t pcr) {

    return getLoggerForPCR_(NULL, pcr, true);
}

void freeLogger(HashMessageLogger *logger) {

    close(logger->fd);
    free(logger->alg_ids);
    RecordList *rl, *tmpl = NULL;

    DL_FOREACH_SAFE(logger->re_list, rl, tmpl) {

        DL_DELETE(logger->re_list, rl);
        freeRecordList(rl);
    }
    HASH_MESSAGE *cur, *tmp;

    HASH_ITER(hh, logger->hm_map, cur, tmp) {
        HASH_DEL(logger->hm_map, cur);
        free_hash_message(cur);
    }
    StsQueue.destroy(logger->que);
    free(logger->mutex);
    memset(logger, 0, sizeof (HashMessageLogger));
    free(logger);
}
