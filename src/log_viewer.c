/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file log_viewer.c
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

#include "log_viewer.h"

#ifdef WHEELFEEDER
WheelFeeder *wfhead = NULL;
#endif

int main(int argc, char *argv[]) {
    int pcr = 16;
    bool expected_pcr = false;
    char* conf_file = "config/uiimd.yml";
    int opt = 0;
    while ((opt = getopt(argc, argv, "p:ec:")) != -1) {
        switch (opt) {
            case 'p':
                pcr = atoi(optarg);
                break;
            case 'e':
                expected_pcr = true;
                break;
            case 'c':
                conf_file = strdup(optarg);
                break;
            default:
                break;

        }
    }
    FILE *fh = fopen(conf_file, "r");
    uiimconf *conf = parse_yaml_conf(fh);
#ifdef WHEELFEEDER
    //DUMMY DIS
    ListRoot lr = {.first = NULL, .tail = NULL, .lock = 0};
    Distribution dis = {.collected = &lr, .sessionHead = NULL, .wfHead = NULL};
    WheelFeeder *logger = getWF(&dis, conf, pcr);
#else
    HashMessageLogger *logger = getLoggerForPCR(conf, pcr);
#endif

    for (ListElement *ele = logger->re_list->next; ele == NULL; ele = ele->next) {
        printRecordList(ele->value);
    }
}
