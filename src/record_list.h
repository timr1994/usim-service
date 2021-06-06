/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file record_list.h
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
#ifndef RECORD_LIST_H
#define RECORD_LIST_H

#include "uiim_service_typedefs.h"
#include <utlist.h>
#include <stdbool.h>
#include "help_functions.h"

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>

#include <hash_message.h>
#include <hash_message_cbor.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha512.h>

#ifdef __cplusplus
extern "C" {
#endif
    
#ifdef WHEELFEEDER
    IN_RC addRecord(WheelFeeder *wf, Record *record, bool extend);
    IN_RC addMultiRecord(WheelFeeder *wf, MultiRecord *mrecord, bool extend);
    TSS2_RC pcrExtend(WheelFeeder *wf, RecordList *rl);
#else
    IN_RC addRecord(HashMessageLogger *logger, Record *record, bool extend);
    void addMultiRecord(HashMessageLogger *logger, MultiRecord *mrecord, bool extend);
    TSS2_RC pcrExtend(HashMessageLogger *logger, RecordList *rl);
#endif
    void freeRecordList(RecordList *rl);
    void printRecordList(RecordList *rl);

#ifdef __cplusplus
}
#endif

#endif /* RECORD_LIST_H */

