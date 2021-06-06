/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file hash_message_record.h
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-04-10
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef HASH_MESSAGE_RECORD_H
#define HASH_MESSAGE_RECORD_H

#define MAX_SIZE_MULTI_RECORD 50

#include <hash_message.h>
#include <hash_message_cbor.h>
#include <cbor_help.h>
#include <utlist.h>
#include <unistd.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha512.h>

#include "uiim_service_typedefs.h"

#ifdef __cplusplus
extern "C" {
#endif


    /**
     * 
     * @param buf
     * @param buf_len
     * @param record
     */
    void recordUnmarshallingFill(uint8_t *buf, size_t buf_len, Record *record);
    /**
     * 
     * @param buf
     * @param buf_len
     * @return 
     */
    Record *recordUnmarshalling(uint8_t *buf, size_t buf_len);
    /**
     * 
     * @param record
     * @return 
     */
    uint8_t *recordMarshalling(Record *record);
    /**
     * 
     * @param record
     * @return 
     */
    size_t getSizeOfRecord(Record *record);



    /**
     * 
     * @param buf
     * @param buf_len
     * @param record
     */
    void multiRecordUnmarshallingFill(uint8_t *buf, size_t buf_len, MultiRecord *record);
    /**
     * 
     * @param buf
     * @param buf_len
     * @return 
     */
    MultiRecord *multiRecordUnmarshalling(uint8_t *buf, size_t buf_len);
    /**
     * 
     * @param record
     * @return 
     */
    uint8_t *multiRecordMarshalling(MultiRecord *record);
    /**
     * 
     * @param fd
     * @param record
     * @return 
     */
    int writeMultiRecord(int fd, MultiRecord *record);
    /**
     * 
     * @param record
     * @return 
     */
    size_t getSizeOfMultiRecord(MultiRecord *record);
    /**
     * 
     * @param mrecord
     * @return 
     */
    uint8_t *setSHA1HashMultiRecord(MultiRecord *mrecord);
    /**
     * 
     * @param mrecord
     * @return 
     */
    uint8_t *setSHA256HashMultiRecord(MultiRecord *mrecord);
    /**
     * 
     * @param mrecord
     * @return 
     */
    uint8_t *setSHA384HashMultiRecord(MultiRecord *mrecord);
    /**
     * 
     * @param mrecord
     * @return 
     */
    uint8_t *setSHA512HashMultiRecord(MultiRecord *mrecord);

#ifdef __cplusplus
}
#endif

#endif /* HASH_MESSAGE_RECORD_H */

