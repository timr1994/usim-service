/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file distributor.h
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-24
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

/* 
 * File:   distributor.h
 * Author: tim
 *
 * Created on 24. Juni 2020, 16:16
 */

#ifndef DISTRIBUTOR_H
#define DISTRIBUTOR_H

#include <utlist.h>

#include "uiim_service_typedefs.h"
#include "wheel_feeder.h"

/**
 * 
 * @param data
 * @return 
 */
void *distributerThread(void *data);

void aquireDistributionLock(Distribution *dis);

void releaseDistributionLock(Distribution *dis);

void stopDistribution(Distribution *dis);

#endif /* DISTRIBUTOR_H */
