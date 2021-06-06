/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file uiimlog.h
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

#ifndef UIIMCONF_H
#define UIIMCONF_H

#include <stdio.h>
#include <yaml.h>
#include <tss2/tss2_tpm2_types.h>
#include <hash_message.h>
#include <netinet/in.h>
#include "uiim_service_typedefs.h"

#ifdef __cplusplus
extern "C" {
#endif

    uiimconf * parse_yaml_conf(FILE *fh);


#ifdef __cplusplus
}
#endif

#endif /* UIIMCONF_H */

