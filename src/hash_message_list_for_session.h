/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file hash_message_list_for_session.h
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

#ifndef HASHMESSAGELIST_H
#define HASHMESSAGELIST_H

#include <stdbool.h>
#include <hash_message.h>
#include "uiim_service_typedefs.h"



#ifdef __cplusplus
extern "C" {
#endif
    
    void freeHML(HM_List *hml);



#ifdef __cplusplus
}
#endif

#endif /* HASHMESSAGELIST_H */

