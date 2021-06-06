/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file wheel_feeder.h
 *  @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 *  @date 2020-06-10
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#ifndef WHEEL_FEEDER_H
#define WHEEL_FEEDER_H

#define LOG_FILE_NAME "/pcr000.log"
#define BREAK_NES(rc) if(rc<=0){break;}



#include "uiim_service_typedefs.h"
#include <utlist.h>
#include <uiim.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <bits/stdint-uintn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <signal.h>

#include <hash_message.h>
#include <hash_message_cbor.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha512.h>

#include "hash_message_record.h"
#include "record_list.h"
#include "util/tpm2_util.h"



#ifdef __cplusplus
extern "C" {
#endif
    /**
     * Initiates a WheelFeeder with the given parameters.
     * @param wf WheelFeeder that should be iniated.
     * @param pcr PCR on which the extend should happen.
     * @param path Path to log directory.
     * @param alg_ids array of algorhims that sould be used for extend.
     * @param alg_ids_len length of given array.
     * @return 
     */
    //IN_RC wf_init(WheelFeeder *wf, uint8_t pcr, const char *path, TPM2_ALG_ID *alg_ids, uint8_t alg_ids_len);
    /**
     * Initiates a WheelFeeder with the given parameters.
     * @param wf WheelFeeder that should be iniated.
     * @param pcr PCR on which the extend should happen.
     * @param path Path to log directory.
     * @param alg_ids array of algorhims that sould be used for extend.
     * @param alg_ids_len length of given array.
     * @return 
     */
    IN_RC wfInit(WheelFeeder *wf, uint8_t pcr, const char *path, TPM2_ALG_ID *alg_ids, uint8_t alg_ids_len, Distribution *dis);
    /**
     * Inserts a RecordList element into the receive queue. The function is thread-safe. 
     * @param wf The WheelFeeder where the element should be added.
     * @param element The RecordList element to be added.
     */
    void wfPut(WheelFeeder *wf, RecordList *element);
    /**
     * Appends all elements of the processing queue to the output list and then changes the receive queue to the new processing queue. The function is thread-safe. 
     * @param wf The WheelFeeder to be rotated.
     */
    void wfRotate(WheelFeeder *wf);
    /**
     * Takes one element from the output list.
     * @param wf The WheelFeeder with the wanted output list.
     * @return A RecordList element form the output list.
     */
    RecordList *wfTake(WheelFeeder *wf);
    /**
     * Takes all elements from the output list.
     * @param wf The WheelFeeder with the wanted output list.
     * @return A RecordList element form the output list.
     */
    //RecordList *wf_take_all(WheelFeeder *wf);
    /**
     * Checks whether the specified algorithm is used in the WheelFeeder.
     * @param wf The WheelFeeder to be checked.
     * @param algId selected algorithm.
     * @return true if the algorithm is used, otherwise false.
     */
    bool isSelected(WheelFeeder *wf, TPM2_ALG_ID algId);
    /**
     * Sends all responses listed in the output list that relate to the session.
     * @param session The session to filter the responses.
     * @return Okay if no error occured.
     */
    //PRO_RC wf_send_for_session(Session *session);
    /**
     * Wrapper function for processing the processing queue.
     * @param data WheelFeeder pointer
     * @return always NULL
     */
    void *wfProcessT(void *data);
    /**
     * Returns the WheelFeeder for the given PCR. If not initiated, it will be initiated.
     * @param headwf Pointer of the WheelFeeder head.
     * @param conf The wanted uiimconf.
     * @param pcr PCR the WheelFeeder should use.
     * @return The WheelFeeder for the given PCR.
     */
    WheelFeeder *getWF(Distribution *dis, uiimconf *conf, uint8_t pcr);
    /**
     * 
     * @param signo
     */
    void sigusr2_handler(int signo);
    /**
     * 
     * @param wf
     */
    void freeWF(WheelFeeder *wf);
#ifdef __cplusplus
}
#endif
#endif /* WHEEL_FEEDER_H */
