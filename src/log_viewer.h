/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file log_viewer.h
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 2020-05-31
 *  
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 *  Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#ifndef LOG_VIEWER_H
#define LOG_VIEWER_H
#include "uiim_service_typedefs.h"
#include "uiimconf.h"
#ifdef WHEELFEEDER
#include "wheel_feeder.h"
#else
#include "hash_message_logger.h"
#endif

#endif /* LOG_VIEWER_H */
