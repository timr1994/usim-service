/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file record_list.c
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

#include <stdlib.h>
#include <tss2/tss2_common.h>
#include "record_list.h"

#ifdef WHEELFEEDER
#include "wheel_feeder.h"
#else
#include "hash_message_logger.h"
#endif

#ifndef WHEELFEEDER

IN_RC addRecord(HashMessageLogger *logger, Record *record, bool extend) {
    RecordList *listAdd = malloc(sizeof (RecordList));
    memset(listAdd, 0, sizeof (RecordList));
    IN_RC rc = EntryInsert;
    listAdd->isMultiRecord = false;
    listAdd->vals.record = record;
    DL_APPEND(logger->re_list, listAdd);
    if (listAdd->prev != logger->re_list) {
        listAdd->index = listAdd->prev->index + 1;
    }
    if (extend) {
        TSS2_RC tssrc = pcrExtend(logger, listAdd);
        if (tssrc != TSS2_RC_SUCCESS) {
            rc = TPMError;
        }
    }
    return rc;
}

void addMultiRecord(HashMessageLogger *logger, MultiRecord *mrecord, bool extend) {
    RecordList *listAdd = malloc(sizeof (RecordList));
    memset(listAdd, 0, sizeof (RecordList));
    static int cc = 1;
    IN_RC rc = EntryInsert;
    listAdd->isMultiRecord = true;
    listAdd->vals.multiRecord = mrecord;
    DL_APPEND(logger->re_list, listAdd);
    if (listAdd->prev != logger->re_list) {
        listAdd->index = listAdd->prev->index + 1;
    }
    if (extend) {
        TSS2_RC tssrc = pcrExtend(logger, listAdd);
        if (tssrc != TSS2_RC_SUCCESS) {
            rc = TPMError;
        }
    }
    for (uint8_t i = 0; i < mrecord->count; i++) {
        volatile IN_RC *inRc = mrecord->records[i]->rc;
        if (mrecord->records[i]->rc != NULL) {
            *(mrecord->records[i]->rc) = rc;
        }

    }
}
#endif


/**
 * @brief Extend a TPM PCR on base of a HASH_MESSAGE
 * 
 * @param hm HASH_MESSAGE to used for extend
 * @return 1 on error, 0 on sucess
 */
#ifdef WHEELFEEDER

TSS2_RC pcrExtend(WheelFeeder *wf, RecordList *rl) {
#else

TSS2_RC pcrExtend(HashMessageLogger *wf, RecordList *rl) {
#endif

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
                if (isSelected(wf, TPM2_ALG_SHA256)) {
                    memcpy(dig.digests[i - digC].digest.sha256, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SHA1:
                if (isSelected(wf, TPM2_ALG_SHA1)) {
                    memcpy(dig.digests[i - digC].digest.sha1, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SHA384:
                if (isSelected(wf, TPM2_ALG_SHA384)) {
                    memcpy(dig.digests[i - digC].digest.sha384, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SHA512:
                if (isSelected(wf, TPM2_ALG_SHA512)) {
                    memcpy(dig.digests[i - digC].digest.sha512, hp[i].hash_data, get_hash_data_size_by_alg_name(hp[i].alg_name));
                } else {
                    digC++;
                }
                break;
            case TPM2_ALG_SM3_256:
                if (isSelected(wf, TPM2_ALG_SM3_256)) {
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
    if ((tss_rc = tpm2_pcr_extend(esys_ctx, wf->pcr, &dig)) != TSS2_RC_SUCCESS) {
        printf("%s", "Error ext");
        Esys_Finalize(&esys_ctx);
        return tss_rc;
    }
    Esys_Finalize(&esys_ctx);

    return TSS2_RC_SUCCESS;
}

#ifdef WHEELFEEDER

IN_RC addRecord(WheelFeeder *wf, Record *record, bool extend) {
    RecordList *add = malloc(sizeof (RecordList));
    memset(add, 0, sizeof (RecordList));
    IN_RC rc = EntryInsert;
    add->isMultiRecord = false;
    add->vals.record = record;
    
    //INDEX ERHÖHEN
    if (!(record->flags & DO_NOT_HANDLE_DUPLICATES)) {
        HASH_ADD_KEYPTR(hh, wf->hm_map, record->hm->event_id, strlen(record->hm->event_id), record->hm);
    }
    if (extend) {
        TSS2_RC tssrc = pcrExtend(wf, add);
        if (tssrc != TSS2_RC_SUCCESS) {
            rc = TPMError;
        }
    }
    return rc;
}

IN_RC addMultiRecord(WheelFeeder *wf, MultiRecord *mrecord, bool extend) {
    RecordList *add = malloc(sizeof (RecordList));
    memset(add, 0, sizeof (RecordList));
    IN_RC rc = EntryInsert;
    add->isMultiRecord = true;
    add->vals.multiRecord = mrecord;
    listAdd(wf->re_list,add);

    for (uint8_t i = 0; i < mrecord->count; i++) {
        if (!(mrecord->records[i]->flags & DO_NOT_HANDLE_DUPLICATES)) {
            HASH_ADD_KEYPTR(hh, wf->hm_map, mrecord->records[i]->hm->event_id, strlen(mrecord->records[i]->hm->event_id), mrecord->records[i]->hm);
        }
    }
    //INDEX ERHÖHEN
    if (extend) {
        TSS2_RC tssrc = pcrExtend(wf, add);
        if (tssrc != TSS2_RC_SUCCESS) {
            rc = TPMError;
        }
    }
    return rc;
}
#endif

void freeRecord(Record *record) {
    free(record->producer);
    free_hash_message(record->hm);
    free(record);
}

void freeMultiRecord(MultiRecord *mre) {
    free(mre->multihash);
    for (int i = 0; i < mre->count; i++) {
        freeRecord(mre->records[i]);
    }
    free(mre->records);
    free_hash_payload(mre->multihash, mre->multihash_size);
    free(mre);
}

void freeRecordList(RecordList *rl) {
    if (rl->isMultiRecord) {
        freeMultiRecord(rl->vals.multiRecord);
    } else {
        freeRecord(rl->vals.record);
    }
    free(rl);

}

char *get_alg_id_string(TPM2_ALG_ID str) {
    if (str == TPM2_ALG_ERROR) {
        return "TPM2_ALG_ERROR";
    } else if (str == TPM2_ALG_RSA) {
        return "TPM2_ALG_RSA";
    } else if (str == TPM2_ALG_TDES) {
        return "TPM2_ALG_TDES";
    } else if (str == TPM2_ALG_SHA) {
        return "TPM2_ALG_SHA";
    } else if (str == TPM2_ALG_SHA1) {
        return "TPM2_ALG_SHA1";
    } else if (str == TPM2_ALG_HMAC) {
        return "TPM2_ALG_HMAC";
    } else if (str == TPM2_ALG_AES) {
        return "TPM2_ALG_AES";
    } else if (str == TPM2_ALG_MGF1) {
        return "TPM2_ALG_MGF1";
    } else if (str == TPM2_ALG_KEYEDHASH) {
        return "TPM2_ALG_KEYEDHASH";
    } else if (str == TPM2_ALG_XOR) {
        return "TPM2_ALG_XOR";
    } else if (str == TPM2_ALG_SHA256) {
        return "TPM2_ALG_SHA256";
    } else if (str == TPM2_ALG_SHA384) {
        return "TPM2_ALG_SHA384";
    } else if (str == TPM2_ALG_SHA512) {
        return "TPM2_ALG_SHA512";
    } else if (str == TPM2_ALG_NULL) {
        return "TPM2_ALG_NULL";
    } else if (str == TPM2_ALG_SM3_256) {
        return "TPM2_ALG_SM3_256";
    } else if (str == TPM2_ALG_SM4) {
        return "TPM2_ALG_SM4";
    } else if (str == TPM2_ALG_RSASSA) {
        return "TPM2_ALG_RSASSA";
    } else if (str == TPM2_ALG_RSAES) {
        return "TPM2_ALG_RSAES";
    } else if (str == TPM2_ALG_RSAPSS) {
        return "TPM2_ALG_RSAPSS";
    } else if (str == TPM2_ALG_OAEP) {
        return "TPM2_ALG_OAEP";
    } else if (str == TPM2_ALG_ECDSA) {
        return "TPM2_ALG_ECDSA";
    } else if (str == TPM2_ALG_ECDH) {
        return "TPM2_ALG_ECDH";
    } else if (str == TPM2_ALG_ECDAA) {
        return "TPM2_ALG_ECDAA";
    } else if (str == TPM2_ALG_SM2) {
        return "TPM2_ALG_SM2";
    } else if (str == TPM2_ALG_ECSCHNORR) {
        return "TPM2_ALG_ECSCHNORR";
    } else if (str == TPM2_ALG_ECMQV) {
        return "TPM2_ALG_ECMQV";
    } else if (str == TPM2_ALG_KDF1_SP800_56A) {
        return "TPM2_ALG_KDF1_SP800_56A";
    } else if (str == TPM2_ALG_KDF2) {
        return "TPM2_ALG_KDF2";
    } else if (str == TPM2_ALG_KDF1_SP800_108) {
        return "TPM2_ALG_KDF1_SP800_108";
    } else if (str == TPM2_ALG_ECC) {
        return "TPM2_ALG_ECC";
    } else if (str == TPM2_ALG_SYMCIPHER) {
        return "TPM2_ALG_SYMCIPHER";
    } else if (str == TPM2_ALG_CAMELLIA) {
        return "TPM2_ALG_CAMELLIA";
    } else if (str == TPM2_ALG_CMAC) {
        return "TPM2_ALG_CMAC";
    } else if (str == TPM2_ALG_CTR) {
        return "TPM2_ALG_CTR";
    } else if (str == TPM2_ALG_SHA3_256) {
        return "TPM2_ALG_SHA3_256";
    } else if (str == TPM2_ALG_SHA3_384) {
        return "TPM2_ALG_SHA3_384";
    } else if (str == TPM2_ALG_SHA3_512) {
        return "TPM2_ALG_SHA3_512";
    } else if (str == TPM2_ALG_OFB) {
        return "TPM2_ALG_OFB";
    } else if (str == TPM2_ALG_CBC) {
        return "TPM2_ALG_CBC";
    } else if (str == TPM2_ALG_CFB) {
        return "TPM2_ALG_CFB";
    } else if (str == TPM2_ALG_ECB) {
        return "TPM2_ALG_ECB";
    } else if (str == TPM2_ALG_FIRST) {
        return "TPM2_ALG_FIRST";
    } else if (str == TPM2_ALG_LAST) {
        return "TPM2_ALG_LAST";
    }
}

void printRecordList(RecordList *rl) {
    if (rl->isMultiRecord) {
        printf("Index: %lu is Multi Record\n", rl->index);
        MultiRecord *mrecord = rl->vals.multiRecord;
        for (int j = 0; j < mrecord->count; j++) {
            Record *record = mrecord->records[j];
            printf("\t\t%d.Record:\n", j + 1);
            printf("\t\tProducer: %s\n", record->producer);
            printf("\t\tEventID: %s\n", record->hm->event_id);
            for (int i = 0; i < record->hm->h_payload_size; i++) {
                char *alg_name = get_alg_id_string(record->hm->h_payload[i].alg_name);
                char *hs = get_hex_string(record->hm->h_payload[i].hash_data, get_hash_data_size_by_alg_name(record->hm->h_payload[i].alg_name));
                printf("\t\t\t %s_HASH: %s\n", alg_name, hs);
            }
        }
        printf("\t\t Combinded Hash:\n");
        for (int i = 0; i < mrecord->multihash_size; i++) {
            printf("\t\t %s_HASH:\t %s\n", get_alg_id_string(mrecord->multihash[i].alg_name), get_hex_string(mrecord->multihash[i].hash_data, get_hash_data_size_by_alg_name(mrecord->multihash[i].alg_name)));
        }

    } else {
        //Hier ist noch ein Fehler
        printf("Index: %lu is Single Record\n", rl->index);
        Record *record = rl->vals.record;
        printf("\tProducer: %s\n", record->producer);
        printf("\tEventID: %s\n", record->hm->event_id);
        for (int i = 0; i < record->hm->h_payload_size; i++) {
            printf("\t\t %s_HASH:\t %s\n", get_alg_id_string(record->hm->h_payload[i].alg_name), get_hex_string(record->hm->h_payload[i].hash_data, get_hash_data_size_by_alg_name(record->hm->h_payload[i].alg_name)));
        }
    }
}