/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file hash_message_record.c
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

#include "hash_message_record.h"

void recordUnmarshallingFill(uint8_t *buf, size_t buf_len, Record *record) {
    QCBORDecodeContext DCtx;
    UsefulBufC bufC;
    QCBORItem item;
    bufC.len = buf_len;
    bufC.ptr = buf;
    record->hm = malloc(sizeof (HASH_MESSAGE));
    memset(record->hm, 0, sizeof (HASH_MESSAGE));
    QCBORDecode_Init(&DCtx, bufC, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetNext(&DCtx, &item);
#ifdef WHEELFEEDER
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 5) {
#else
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 4) {
#endif
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            record->producer = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
            record->producer[item.val.string.len] = '\0';
        }
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            record->hm->event_id = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
            record->hm->event_id[item.val.string.len] = '\0';
            record->hm->event_id_length = item.val.string.len;
        }
#ifdef WHEELFEEDER
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_INT64) {
            record->flags = item.val.int64;
        }
#endif
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            record->hm->event_length = item.val.string.len;
            record->hm->event = memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len);
        }
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_ARRAY) {
            record->hm->h_payload_size = item.val.uCount;
            record->hm->h_payload = calloc(record->hm->h_payload_size, sizeof (hash_payload));
            memset(record->hm->h_payload, 0, record->hm->h_payload_size * sizeof (hash_payload));
            for (uint8_t i = 0; i < record->hm->h_payload_size; i++) {
                QCBORDecode_GetNext(&DCtx, &item);
                if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 2) {
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_INT64) {
                        record->hm->h_payload[i].alg_name = item.val.int64;
                        record->hm->h_payload[i].hash_data = malloc(get_hash_data_size_by_alg_name(record->hm->h_payload[i].alg_name));
                        memset(record->hm->h_payload[i].hash_data, 0, get_hash_data_size_by_alg_name(record->hm->h_payload[i].alg_name));
                    }
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_BYTE_STRING && get_hash_data_size_by_alg_name(record->hm->h_payload[i].alg_name) == item.val.string.len) {
                        memcpy(record->hm->h_payload[i].hash_data, item.val.string.ptr, item.val.string.len);
                    }
                }
            }
        }

    }
    QCBORDecode_Finish(&DCtx);
}

Record *recordUnmarshalling(uint8_t *buf, size_t buf_len) {
    Record *record = malloc(sizeof (Record));
    memset(record, 0, sizeof (Record));
    recordUnmarshallingFill(buf, buf_len, record);
    return record;
}

uint8_t *recordMarshalling(Record *record) {
    UsefulBuf buf;
    buf.len = getSizeOfRecord(record);
    buf.ptr = malloc(buf.len);
    QCBOREncodeContext eCtx;
    QCBOREncode_Init(&eCtx, buf);
    QCBOREncode_OpenArray(&eCtx);
    QCBOREncode_AddSZString(&eCtx, record->producer);
    QCBOREncode_AddSZString(&eCtx, record->hm->event_id);
#ifdef WHEELFEEDER
    QCBOREncode_AddInt64(&eCtx, record->flags);
#endif
    QCBOREncode_AddBytes(&eCtx, (UsefulBufC){record->hm->event, record->hm->event_length});
    QCBOREncode_OpenArray(&eCtx);
    for (uint16_t i = 0; i < record->hm->h_payload_size; i++) {
        QCBOREncode_OpenArray(&eCtx);
        QCBOREncode_AddUInt64(&eCtx, record->hm->h_payload[i].alg_name);
        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){record->hm->h_payload[i].hash_data, get_hash_data_size_by_alg_name(record->hm->h_payload[i].alg_name)});
        QCBOREncode_CloseArray(&eCtx);
    }
    QCBOREncode_CloseArray(&eCtx);
    QCBOREncode_CloseArray(&eCtx);
    UsefulBufC Encoded;
    QCBOREncode_Finish(&eCtx, &Encoded);
    uint8_t *reBuf = malloc(Encoded.len);
    memcpy(reBuf, Encoded.ptr, Encoded.len);
    free(buf.ptr);
    return reBuf;

}

size_t getSizeOfRecord(Record *record) {
#ifdef WHEELFEEDER
    return get_size_of_hash_message(record->hm) + get_size_for_cbor_string(record->producer) + get_size_for_cbor_uint(record->flags);
#else
    return get_size_of_hash_message(record->hm) + get_size_for_cbor_string(record->producer);
#endif
}

int writeMultiRecord(int fd, MultiRecord *record) {
    uint64_t size = getSizeOfMultiRecord(record);
    write(fd, &size, sizeof (size));
    //WRITE TYP
    write(fd, &(RTM), sizeof (RTM));
    uint8_t *buf = multiRecordMarshalling(record);
    write(fd, buf, size);
    free(buf);
}

void multiRecordUnmarshallingFill(uint8_t *buf, size_t buf_len, MultiRecord *mrecord) {
    QCBORDecodeContext DCtx;
    UsefulBufC bufC;
    QCBORItem item;
    bufC.len = buf_len;
    bufC.ptr = buf;
    QCBORDecode_Init(&DCtx, bufC, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetNext(&DCtx, &item);
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 2) {
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_ARRAY) {
            mrecord->count = item.val.uCount;
            mrecord->records = calloc(mrecord->count, sizeof (Record));
            for (uint8_t i = 0; i < mrecord->count; i++) {
                QCBORDecode_GetNext(&DCtx, &item);
                Record *record = malloc(sizeof (Record));
                memset(record, 0, sizeof (Record));
                mrecord->records[i] = record;
#ifdef WHEELFEEDER
                record->statusCode = Nothing;
#else
                record->rc = NULL;
#endif

                record->hm = malloc(sizeof (HASH_MESSAGE));
                memset(record->hm, 0, sizeof (HASH_MESSAGE));
#ifdef WHEELFEEDER
                if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 5) {
#else
                if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 4) {
#endif
                    QCBORDecode_GetNext(&DCtx, &item);

                    if (item.uDataType == QCBOR_TYPE_TEXT_STRING) {
                        record->producer = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
                        record->producer[item.val.string.len] = '\0';
                    }

                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_TEXT_STRING) {
                        record->hm->event_id = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
                        record->hm->event_id[item.val.string.len] = '\0';
                        record->hm->event_id_length = item.val.string.len;
                    }
#ifdef WHEELFEEDER
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_INT64) {
                        record->flags = item.val.int64;
                    }
#endif
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
                        record->hm->event_length = item.val.string.len;
                        record->hm->event = memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len);
                    }
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_ARRAY) {
                        record->hm->h_payload_size = item.val.uCount;
                        record->hm->h_payload = calloc(record->hm->h_payload_size, sizeof (hash_payload));
                        memset(record->hm->h_payload, 0, record->hm->h_payload_size * sizeof (hash_payload));
                        for (uint8_t j = 0; j < record->hm->h_payload_size; j++) {
                            QCBORDecode_GetNext(&DCtx, &item);
                            if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 2) {
                                QCBORDecode_GetNext(&DCtx, &item);
                                if (item.uDataType == QCBOR_TYPE_INT64) {
                                    record->hm->h_payload[j].alg_name = item.val.int64;
                                    record->hm->h_payload[j].hash_data = malloc(get_hash_data_size_by_alg_name(record->hm->h_payload[j].alg_name));
                                    memset(record->hm->h_payload[j].hash_data, 0, get_hash_data_size_by_alg_name(record->hm->h_payload[j].alg_name));
                                }
                                QCBORDecode_GetNext(&DCtx, &item);
                                if (item.uDataType == QCBOR_TYPE_BYTE_STRING && get_hash_data_size_by_alg_name(record->hm->h_payload[j].alg_name) == item.val.string.len) {
                                    memcpy(record->hm->h_payload[j].hash_data, item.val.string.ptr, item.val.string.len);
                                }
                            }
                        }
                    }

                }
            }
            QCBORDecode_GetNext(&DCtx, &item);
            if (item.uDataType == QCBOR_TYPE_ARRAY) {
                mrecord->multihash_size = item.val.uCount;
                mrecord->multihash = calloc(mrecord->multihash_size, sizeof (hash_payload));
                memset(mrecord->multihash, 0, mrecord->multihash_size * sizeof (hash_payload));
                for (uint16_t i = 0; i < mrecord->multihash_size; i++) {
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 2) {
                        QCBORDecode_GetNext(&DCtx, &item);
                        if (item.uDataType == QCBOR_TYPE_INT64) {
                            mrecord->multihash[i].alg_name = item.val.int64;
                            mrecord->multihash[i].hash_data = malloc(get_hash_data_size_by_alg_name(mrecord->multihash[i].alg_name));
                            memset(mrecord->multihash[i].hash_data, 0, get_hash_data_size_by_alg_name(mrecord->multihash[i].alg_name));
                        }
                        QCBORDecode_GetNext(&DCtx, &item);
                        if (item.uDataType == QCBOR_TYPE_BYTE_STRING && get_hash_data_size_by_alg_name(mrecord->multihash[i].alg_name) == item.val.string.len) {
                            memcpy(mrecord->multihash[i].hash_data, item.val.string.ptr, item.val.string.len);
                        }
                    }
                }
            }
        }

    }



    QCBORDecode_Finish(&DCtx);
}

MultiRecord *multiRecordUnmarshalling(uint8_t *buf, size_t buf_len) {
    MultiRecord *mrecord = malloc(sizeof (MultiRecord));
    memset(mrecord, 0, sizeof (MultiRecord));
    multiRecordUnmarshallingFill(buf, buf_len, mrecord);
    return mrecord;
}

uint8_t *multiRecordMarshalling(MultiRecord *mrecord) {
    UsefulBuf buf;
    buf.len = getSizeOfMultiRecord(mrecord);
    buf.ptr = malloc(buf.len);
    QCBOREncodeContext eCtx;
    QCBOREncode_Init(&eCtx, buf);
    QCBOREncode_OpenArray(&eCtx);
    QCBOREncode_OpenArray(&eCtx); //records array
    for (uint8_t i = 0; i < mrecord->count; i++) {
        Record *record = mrecord->records[i];
        QCBOREncode_OpenArray(&eCtx);
        QCBOREncode_AddSZString(&eCtx, record->producer);
        QCBOREncode_AddSZString(&eCtx, record->hm->event_id);
#ifdef WHEELFEEDER
        QCBOREncode_AddInt64(&eCtx, record->flags);
#endif
        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){record->hm->event, record->hm->event_length});
        QCBOREncode_OpenArray(&eCtx);
        for (uint16_t j = 0; j < record->hm->h_payload_size; j++) {
            QCBOREncode_OpenArray(&eCtx);
            QCBOREncode_AddUInt64(&eCtx, record->hm->h_payload[j].alg_name);
            QCBOREncode_AddBytes(&eCtx, (UsefulBufC){record->hm->h_payload[j].hash_data, get_hash_data_size_by_alg_name(record->hm->h_payload[j].alg_name)});
            QCBOREncode_CloseArray(&eCtx);
        }
        QCBOREncode_CloseArray(&eCtx);
        QCBOREncode_CloseArray(&eCtx);
    }
    QCBOREncode_CloseArray(&eCtx);
    QCBOREncode_OpenArray(&eCtx);
    for (uint8_t i = 0; i < mrecord->multihash_size; i++) {
        QCBOREncode_OpenArray(&eCtx);
        QCBOREncode_AddUInt64(&eCtx, mrecord->multihash[i].alg_name);
        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){mrecord->multihash[i].hash_data, get_hash_data_size_by_alg_name(mrecord->multihash[i].alg_name)});
        QCBOREncode_CloseArray(&eCtx);
    }
    QCBOREncode_CloseArray(&eCtx);
    QCBOREncode_CloseArray(&eCtx);

    UsefulBufC Encoded;
    QCBOREncode_Finish(&eCtx, &Encoded);
    //printHex(buf.ptr, buf.len);
    uint8_t *reBuf = memcpy(malloc(Encoded.len), Encoded.ptr, Encoded.len);
    free(buf.ptr);
    return reBuf;

}

size_t getSizeOfMultiRecord(MultiRecord *mrecord) {
    size_t size = get_size_for_cbor_uint(2); //array 2;
    size += get_size_for_cbor_uint(mrecord->count);
    for (uint8_t i = 0; i < mrecord->count; i++) {
        size += getSizeOfRecord(mrecord->records[i]);
    }
    size += get_size_for_cbor_uint(mrecord->multihash_size);
    for (int i = 0; i < mrecord->multihash_size; i++) {
        size += 1; //sub array never have more than 2 elements, so is array type identfifer with array length is 1 byte
        size += get_size_for_cbor_uint(mrecord->multihash[i].alg_name);
        size += get_size_for_cbor_uint(get_hash_data_size_by_alg_name(mrecord->multihash[i].alg_name));
        size += get_hash_data_size_by_alg_name(mrecord->multihash[i].alg_name);
    }
    return size;
}

uint8_t *setSHA512HashMultiRecord(MultiRecord *mrecord) {
    uint8_t *start = (uint8_t *) calloc(get_hash_data_size_by_alg_name(TPM2_ALG_SHA512), sizeof (uint8_t));
    memset(start, 0, get_hash_data_size_by_alg_name(TPM2_ALG_SHA512));
    mbedtls_sha512_context ctx;
    for (uint8_t i = 0; i < mrecord->count; i++) {
        HASH_MESSAGE *act = mrecord->records[i]->hm;
        for (int j = 0; j < act->h_payload_size; j++) {
            if (act->h_payload[j].alg_name == TPM2_ALG_SHA512) {
                mbedtls_sha512_init(&ctx);
                mbedtls_sha512_starts_ret(&ctx, 0);
                mbedtls_sha512_update_ret(&ctx, start, get_hash_data_size_by_alg_name(TPM2_ALG_SHA512));
                mbedtls_sha512_update_ret(&ctx, act->h_payload[j].hash_data, get_hash_data_size_by_alg_name(TPM2_ALG_SHA512));
                mbedtls_sha512_finish_ret(&ctx, start);
            }
        }
    }
    //}
    mbedtls_sha512_free(&ctx);
    mrecord->multihash = realloc(mrecord->multihash, (mrecord->multihash_size + 1) * sizeof (hash_payload));
    mrecord->multihash[mrecord->multihash_size].hash_data = start;
    mrecord->multihash[mrecord->multihash_size].alg_name = TPM2_ALG_SHA512;
    mrecord->multihash_size++;
    return start;
}

uint8_t *setSHA384HashMultiRecord(MultiRecord *mrecord) {
    uint8_t *start = malloc(get_hash_data_size_by_alg_name(TPM2_ALG_SHA384));
    memset(start, 0, get_hash_data_size_by_alg_name(TPM2_ALG_SHA384));
    mbedtls_sha512_context ctx;
    for (uint8_t i = 0; i < mrecord->count; i++) {
        HASH_MESSAGE *act = mrecord->records[i]->hm;
        for (int j = 0; j < act->h_payload_size; j++) {
            if (act->h_payload[j].alg_name == TPM2_ALG_SHA384) {
                mbedtls_sha512_init(&ctx);
                mbedtls_sha512_starts_ret(&ctx, 1);
                mbedtls_sha512_update_ret(&ctx, start, get_hash_data_size_by_alg_name(TPM2_ALG_SHA384));
                mbedtls_sha512_update_ret(&ctx, act->h_payload[j].hash_data, get_hash_data_size_by_alg_name(TPM2_ALG_SHA384));
                mbedtls_sha512_finish_ret(&ctx, start);
            }
        }
    }
    //}
    mbedtls_sha512_free(&ctx);
    mrecord->multihash = realloc(mrecord->multihash, (mrecord->multihash_size + 1) * sizeof (hash_payload));
    mrecord->multihash[mrecord->multihash_size].hash_data = start;
    mrecord->multihash[mrecord->multihash_size].alg_name = TPM2_ALG_SHA384;
    mrecord->multihash_size++;
    return start;
}

uint8_t *setSHA256HashMultiRecord(MultiRecord *mrecord) {
    uint8_t *start = malloc(get_hash_data_size_by_alg_name(TPM2_ALG_SHA256));
    memset(start, 0, get_hash_data_size_by_alg_name(TPM2_ALG_SHA256));
    mbedtls_sha256_context ctx;
    for (uint8_t i = 0; i < mrecord->count; i++) {
        HASH_MESSAGE *act = mrecord->records[i]->hm;
        for (int j = 0; j < act->h_payload_size; j++) {
            if (act->h_payload[j].alg_name == TPM2_ALG_SHA256) {
                mbedtls_sha256_init(&ctx);
                mbedtls_sha256_starts_ret(&ctx, 0);
                mbedtls_sha256_update_ret(&ctx, start, get_hash_data_size_by_alg_name(TPM2_ALG_SHA256));
                mbedtls_sha256_update_ret(&ctx, act->h_payload[j].hash_data, get_hash_data_size_by_alg_name(TPM2_ALG_SHA256));
                mbedtls_sha256_finish_ret(&ctx, start);
            }
        }
    }
    //}
    mbedtls_sha256_free(&ctx);
    mrecord->multihash = realloc(mrecord->multihash, (mrecord->multihash_size + 1) * sizeof (hash_payload));
    mrecord->multihash[mrecord->multihash_size].hash_data = start;
    mrecord->multihash[mrecord->multihash_size].alg_name = TPM2_ALG_SHA256;
    mrecord->multihash_size++;
    return start;
}

uint8_t *setSHA1HashMultiRecord(MultiRecord *mrecord) {
    uint8_t *start = malloc(get_hash_data_size_by_alg_name(TPM2_ALG_SHA1));
    memset(start, 0, get_hash_data_size_by_alg_name(TPM2_ALG_SHA1));
    mbedtls_sha1_context ctx;
    for (uint8_t i = 0; i < mrecord->count; i++) {
        HASH_MESSAGE *act = mrecord->records[i]->hm;
        for (int j = 0; j < act->h_payload_size; j++) {
            if (act->h_payload[j].alg_name == TPM2_ALG_SHA1) {
                mbedtls_sha1_init(&ctx);
                mbedtls_sha1_starts_ret(&ctx);
                mbedtls_sha1_update_ret(&ctx, start, get_hash_data_size_by_alg_name(TPM2_ALG_SHA1));
                mbedtls_sha1_update_ret(&ctx, act->h_payload[j].hash_data, get_hash_data_size_by_alg_name(TPM2_ALG_SHA1));
                mbedtls_sha1_finish_ret(&ctx, start);
            }
        }
    }
    //}
    mbedtls_sha1_free(&ctx);
    mrecord->multihash = realloc(mrecord->multihash, (mrecord->multihash_size + 1) * sizeof (hash_payload));
    mrecord->multihash[mrecord->multihash_size].hash_data = start;
    mrecord->multihash[mrecord->multihash_size].alg_name = TPM2_ALG_SHA1;
    mrecord->multihash_size++;
    return start;
}

