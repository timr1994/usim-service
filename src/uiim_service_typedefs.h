/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file uiim_service_typedefs.h
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-04-28
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef UIIM_SERVICE_TYPEDEFS_H
#define UIIM_SERVICE_TYPEDEFS_H

/* #undef WHEELFEEDER */

#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <hash_message.h>
#include "sts_queue/sts_queue.h"


#define RECORD_TYPE_ONE 0x0
#define RECORD_TYPE_MULTI 0x1

static const uint8_t RTO = RECORD_TYPE_ONE;
static const uint8_t RTM = RECORD_TYPE_MULTI;

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct record {
        char *producer;
        HASH_MESSAGE *hm;
#ifdef WHEELFEEDER
        uint16_t sessionId;
        uint16_t seqNum;
        uint8_t flags;
        IN_RC statusCode;
#else
        volatile IN_RC *rc; //Null if not que ele
#endif
    } Record;

    typedef struct MultiRecord {
        Record **records;
        uint8_t volatile count;
        hash_payload *multihash;
        uint8_t volatile multihash_size;
    } MultiRecord;

    typedef struct record_list {
        bool isMultiRecord;
        uint64_t index;

        union {
            Record *record;
            MultiRecord *multiRecord;
        } vals;
        struct record_list *prev;
        struct record_list *next;
    } RecordList;
#define ELEMENT_MTSL RecordList
#include "mtsl/mtsl.h"



    typedef struct HashMessageLogger {
        uint8_t pcr;
        int key;
        uint64_t counter;
        int fd;
        TPM2_ALG_ID *alg_ids;
        uint8_t alg_ids_len;
        pthread_mutex_t *mutex;
        HASH_MESSAGE *hm_map;
        RecordList *re_list;
        StsHeader *que;
        UT_hash_handle hh;
    } HashMessageLogger;

    typedef enum PRO_RC {
        Okay,
        SessionInitated,
        InvalidMessageReceived,
        ErrorRead,
        ErrorWrite,
        SessionInitatedFail,
        ConnectionClosed,
        NothingToProcess,
    } PRO_RC;

    typedef struct HM_List {
        HASH_MESSAGE *hm;
        uint16_t seqNum;
        IN_RC volatile rc;
        bool answered;
        struct HM_List *next;
    } HM_List;
#ifdef WHEELFEEDER

    typedef struct wheelFeeder {
        ListRoot *inQueue;
        ListRoot *outQueue;
        ListRoot *processQueue;
        ListRoot *re_list;
        uint8_t pcr;
        int key;
        int logfile;
        TPM2_ALG_ID *alg_ids;
        uint8_t alg_ids_len;
        HASH_MESSAGE *hm_map;
        UT_hash_handle hh;
        pthread_t threadID;
        pthread_rwlock_t *userRWLock;
        int volatile user;
        pthread_cond_t *mesIn;
        pthread_mutex_t *mesInMutex;
        pthread_cond_t *somethinInQueue;
    } WheelFeeder;
#endif

    typedef struct session {
        uint16_t sessionId;
        uint8_t pcr;
        char *producer;
        int socket;
        uint8_t flags;
        TPM2_ALG_ID *alg_ids;
        uint8_t alg_ids_len;
#ifdef WHEELFEEDER
        WheelFeeder *wf;
        pthread_t threadID_r;
        bool closed;
#else
        HashMessageLogger *logger;
        pthread_t threadID;
#endif
        HM_List *lh;
        UT_hash_handle hh;
    } Session;


#ifdef WHEELFEEDER
    typedef struct distribution{
        Session *sessionHead;
        WheelFeeder *wfHead;
        ListRoot *collected;
        volatile int lock;
        volatile int run;
        pthread_cond_t *somethinInQueue;
        pthread_mutex_t *sIQMutex;
    } Distribution;
#endif
    typedef struct header {
        uint16_t sessionId;
        uint16_t seqNum;
        uint32_t len;
    } Header;

    typedef struct sesIn {
        uint8_t pcr;
        uint8_t flags;
        uint32_t len_producer;
        char *producer;
    } SessionInit;

    typedef enum log_typ {
        CBOR,
        CBORHex,
        HR
    } LOG_TYP;

    typedef struct uiimconf {
        /* Global variable with file for log output*/
        char *LOG_OUTPUT_PATH;
        /* Address where the uiimd should listen, default is 127.0.0.1 */
        in_addr_t ADDRESS;
        /* Port the service should listen */
        int PORT;
        /* Array with selected hash algorithms*/
        TPM2_ALG_ID *alg_ids;
        /* Length of the alg_ids array */
        uint8_t alg_ids_len;
        /* Selected typ for output */
        LOG_TYP logtyp;
    } uiimconf;


#ifdef __cplusplus
}
#endif

#endif /* UIIM_SERVICE_TYPEDEFS_H */

