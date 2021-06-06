/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file wf_session.h
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-10
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#ifndef WF_SESSION_H
#define WF_SESSION_H

#include "wheel_feeder.h"
#include "session_helper.h"
#include <sys/random.h>
#include <signal.h>

void free_session(Session *ses);
void *processNewMessagesT(void *data);
//void *process_out_queue_t(void *data);
Session *wfCreateSession(Distribution *dis, int socket, uiimconf *conf);
#endif /* WF_SESSION_H */
