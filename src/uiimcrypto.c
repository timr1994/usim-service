/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file uiimcrypto.c
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-03-23
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "uiimcrypto.h"
#include "uiim_service_typedefs.h"

/*
 * @brief Calculates SHA1 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t *calculate_pcr_hash_SHA1(RecordList *record_list) {
    uint8_t *start = (uint8_t *) calloc(get_hash_data_size_by_alg_name(TPM2_ALG_SHA1), sizeof (uint8_t));
    memset(start, 0, get_hash_data_size_by_alg_name(TPM2_ALG_SHA1));
    mbedtls_sha1_context ctx;
    RecordList *actEle;

    LL_FOREACH(record_list, actEle) {
        hash_payload *hp = NULL;
        uint8_t size = 0;
        if (actEle->isMultiRecord) {
            hp = actEle->vals.multiRecord->multihash;
            size = actEle->vals.multiRecord->multihash_size;
        } else {
            hp = actEle->vals.record->hm->h_payload;
            size = actEle->vals.record->hm->h_payload_size;
        }
        for (int j = 0; j < size; j++) {
            if (hp[j].alg_name == TPM2_ALG_SHA1) {
                mbedtls_sha1_init(&ctx);
                mbedtls_sha1_starts_ret(&ctx);
                mbedtls_sha1_update_ret(&ctx, start, get_hash_data_size_by_alg_name(TPM2_ALG_SHA1));
                mbedtls_sha1_update_ret(&ctx, hp[j].hash_data, get_hash_data_size_by_alg_name(TPM2_ALG_SHA1));
                mbedtls_sha1_finish_ret(&ctx, start);
            }
        }
    }


    mbedtls_sha1_free(&ctx);
    return start;
}

/*
 * @brief Calculates SHA256 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t *calculate_pcr_hash_SHA256(RecordList *record_list) {
    uint8_t *start = calloc(get_hash_data_size_by_alg_name(TPM2_ALG_SHA256), sizeof (uint8_t));
    memset(start, 0, get_hash_data_size_by_alg_name(TPM2_ALG_SHA256));
    mbedtls_sha256_context ctx;

    RecordList *actEle;

    LL_FOREACH(record_list, actEle) {
        hash_payload *hp = NULL;
        uint8_t size = 0;
        if (actEle->isMultiRecord) {
            hp = actEle->vals.multiRecord->multihash;
            size = actEle->vals.multiRecord->multihash_size;
        } else {
            hp = actEle->vals.record->hm->h_payload;
            size = actEle->vals.record->hm->h_payload_size;
        }
        for (int j = 0; j < size; j++) {
            if (hp[j].alg_name == TPM2_ALG_SHA256) {
                mbedtls_sha256_init(&ctx);
                mbedtls_sha256_starts_ret(&ctx, 0);
                mbedtls_sha256_update_ret(&ctx, start, get_hash_data_size_by_alg_name(TPM2_ALG_SHA256));
                mbedtls_sha256_update_ret(&ctx, hp[j].hash_data, get_hash_data_size_by_alg_name(TPM2_ALG_SHA256));
                mbedtls_sha256_finish_ret(&ctx, start);
            }
        }
    }

    mbedtls_sha256_free(&ctx);
    return start;
}

/*
 * @brief Calculates SHA512 or SHA384 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 * @param[in] is384 1 if is for SHA384 or 0 for SHA512
 * @param[in] algId Selected hash.
 */
uint8_t * calculate_pcr_hash_SHA512_(RecordList *record_list, int is384, TPM2_ALG_ID algId) {
    uint8_t *start = calloc(get_hash_data_size_by_alg_name(algId), sizeof (uint8_t));
    memset(start, 0, get_hash_data_size_by_alg_name(algId));
    mbedtls_sha512_context ctx;

    RecordList *actEle;

    LL_FOREACH(record_list, actEle) {
        hash_payload *hp = NULL;
        uint8_t size = 0;
        if (actEle->isMultiRecord) {
            hp = actEle->vals.multiRecord->multihash;
            size = actEle->vals.multiRecord->multihash_size;
        } else {
            hp = actEle->vals.record->hm->h_payload;
            size = actEle->vals.record->hm->h_payload_size;
        }
        for (int j = 0; j < size; j++) {
            if (hp[j].alg_name == algId) {
                mbedtls_sha512_init(&ctx);
                mbedtls_sha512_starts_ret(&ctx, is384);
                mbedtls_sha512_update_ret(&ctx, start, get_hash_data_size_by_alg_name(algId));
                mbedtls_sha512_update_ret(&ctx, hp[j].hash_data, get_hash_data_size_by_alg_name(algId));
                mbedtls_sha512_finish_ret(&ctx, start);
            }
        }
    }

    mbedtls_sha512_free(&ctx);
    return start;
}

/*
 * @brief Calculates SHA512 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t * calculate_pcr_hash_SHA512(RecordList *record_list) {
    return calculate_pcr_hash_SHA512_(record_list, 0, TPM2_ALG_SHA512);
}

/*
 * @brief Calculates SHA384 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t * calculate_pcr_hash_SHA384(RecordList *record_list) {
    return calculate_pcr_hash_SHA512_(record_list, 1, TPM2_ALG_SHA384);
}
