/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file hash_message_logger.h
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

#ifndef HASH_MESSAGE_LOGGER_H
#define HASH_MESSAGE_LOGGER_H

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <bits/stdint-uintn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>

#include <hash_message.h>
#include <hash_message_cbor.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha512.h>

#include "util/tpm2_util.h"
#include "sts_queue/sts_queue.h"
#include "hash_message_record.h"
#include "record_list.h"
#include "uiimconf.h"
#include "service.h"
#include "help_functions.h"


#ifdef __cplusplus
extern "C" {
#endif
    IN_RC loggerInit(HashMessageLogger *logger, uint8_t pcr, const char *path, TPM2_ALG_ID *alg_ids, uint8_t alg_ids_len);
    IN_RC logHashMessage(HashMessageLogger *logger, const char *producer, HASH_MESSAGE *hm);
    IN_RC hashMessageExists(HashMessageLogger *logger, HASH_MESSAGE *hm);
    HashMessageLogger *getLoggerForPCR(uiimconf *conf, uint8_t pcr);
    HashMessageLogger *getLoggerForPCRToFree(uint8_t pcr);
    void logMultipleHashMessages(HashMessageLogger *logger, const char *producer, HASH_MESSAGE *hm, volatile IN_RC  *rc);
    bool isSelected(HashMessageLogger *logger, TPM2_ALG_ID algId);
    void processQueue(HashMessageLogger *logger, bool endExpected);
    void freeLogger(HashMessageLogger *logger);
    
    TSS2_RC pcrExtend(HashMessageLogger *logger, RecordList *rl);
    
    
    void setAllHashMultiRecord(HashMessageLogger *logger, MultiRecord *mrecord);


#ifdef __cplusplus
}
#endif

#endif /* HASH_MESSAGE_LOGGER_H */

