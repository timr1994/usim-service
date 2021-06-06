/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file service.h
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-01-13
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef SERIVCE_H
#define SERIVCE_H

#include <stdbool.h>
#include <hash_message.h>
#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h>
#include <fcntl.h>
#include "uiim_service_typedefs.h"
#include "uiimconf.h"
#ifndef WHEELFEEDER
#include "session.h"
#else
#include "wf_session.h"
#include "distributor.h"
#include <unistd.h>
#include "wheel_feeder.h"
#endif







#ifdef __cplusplus
extern "C" {
#endif




#ifdef __cplusplus
}
#endif

#endif /* SERIVCE_H */

