/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file uiimcrypto.h
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

#ifndef UIIMCRYPTO_H
#define UIIMCRYPTO_H

#include <hash_message.h>
#include <utlist.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha512.h>
#include "hash_message_list_for_session.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
 * @brief Calculates SHA1 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t *calculate_pcr_hash_SHA1(hash_message_lh *hm_list);
/*
 * @brief Calculates SHA256 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t *calculate_pcr_hash_SHA256(hash_message_lh *hm_list);
/*
 * @brief Calculates SHA512 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t * calculate_pcr_hash_SHA512(hash_message_lh *hm_list);
/*
 * @brief Calculates SHA384 hash for a PCR on base of a HASH_MESSAGE list.
 * 
 * @param[in] pcr Selected PCR for which the hash should be calculated.
 * @param[in] hm_list Head of the list.
 */
uint8_t * calculate_pcr_hash_SHA384(uint8_t pcr, hash_message_lh *hm_list);



#ifdef __cplusplus
}
#endif

#endif /* UIIMCRYPTO_H */

