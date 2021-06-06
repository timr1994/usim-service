/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file hash_message_list_for_session.c
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-03-24
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "hash_message_list_for_session.h"

void freeHML(HM_List *hml) {
    free_hash_message(hml->hm);
    free(hml);
}

HM_List *HMLclone(HM_List *hml) {
    HM_List *clone = malloc(sizeof (HM_List));
    memset(clone, 0, sizeof (HM_List));
    clone->answered = hml->answered;
    return clone;
}


