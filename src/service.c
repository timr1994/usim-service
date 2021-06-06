/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file service.c
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

#include <signal.h>

#include "service.h"
#include "wf_session.h"


#define SA struct sockaddr 
#define MAX_CLIENTS 10

Session *sesHead = NULL;
#ifdef WHEELFEEDER
WheelFeeder *wfHead = NULL;
Distribution *dis = NULL;
pthread_t disThread = {0};
#endif
#ifndef WHEELFEEDER

void freeAll() {
    Session *current_session, *tmp;

    HASH_ITER(hh, sesHead, current_session, tmp) {
        HASH_DEL(sesHead, current_session);
        int rcpk = pthread_kill(current_session->threadID, SIGUSR2);
        if (rcpk == 0) {
            pthread_join(current_session->threadID, NULL);
            free_session(current_session);
        }

    }
}
#else

void freeAll() {
    Session *actSes, *tmp;

    HASH_ITER(hh, dis->sessionHead, actSes, tmp) {
        HASH_DEL(dis->sessionHead, actSes);
        int rcpk = pthread_kill(actSes->threadID_r, SIGUSR2);
        if (rcpk == 0) {
            pthread_join(actSes->threadID_r, NULL);
        }
        free_session(actSes);
    }
    WheelFeeder *actWf, *tmpWf;

    HASH_ITER(hh, dis->wfHead, actWf, tmpWf) {
        HASH_DEL(dis->wfHead, actWf);
        int rcpk = pthread_kill(actWf->threadID, SIGUSR2);
        if (rcpk == 0) {
            pthread_join(actWf->threadID, NULL);
        }
        freeWF(actWf);
    }
    int size = 0;
    RecordList **arr = toArrayAndRemove(dis->collected, &size);
    for (int i = 0; i < size; i++) {
        freeRecordList(arr[i]);
    }
    //free(arr);
    free(dis->collected);
}
#endif

void
sigint_handler(int signo, siginfo_t *sinfo, void *context) {
    stopDistribution(dis);
    freeAll();
    exit(0);
}

void
sigalarm_handler(int signo, siginfo_t *sinfo, void *context) {
    Session *tmp = {0};
    Session *ele = {0};

    HASH_ITER(hh, sesHead, ele, tmp) {
        if (ele->closed) {
            HASH_DEL(sesHead, ele);
            pthread_join(ele->threadID_r, NULL);
            pthread_rwlock_wrlock(ele->wf->userRWLock);
            ele->wf->user--;
            pthread_rwlock_unlock(ele->wf->userRWLock);
            free(ele->alg_ids);
            free(ele->lh);
            free(ele->producer);
            free(ele);
        }
    }
    WheelFeeder *tmpW = {0};
    WheelFeeder *eleW = {0};

    HASH_ITER(hh, wfHead, eleW, tmpW) {
        pthread_rwlock_rdlock(eleW->userRWLock);
        if (eleW->user == 0) {
            //stoppen oder loeschen?
        }
        pthread_rwlock_unlock(eleW->userRWLock);
    }


}

int main(int argc, char *argv[]) {
    struct sigaction act;
    struct sigaction alarmSig;
    dis = malloc(sizeof (Distribution));
    dis->collected = malloc(sizeof (ListRoot));
    dis->collected->first = NULL;
    dis->collected->tail = NULL;
    dis->collected->lock = 0;
    dis->sessionHead = sesHead;
    dis->wfHead = wfHead;
    dis->run = 1;
    dis->somethinInQueue = malloc(sizeof (pthread_cond_t));
    pthread_cond_init(dis->somethinInQueue, 0);
    dis->sIQMutex = malloc(sizeof (pthread_mutex_t));
    pthread_mutex_init(dis->sIQMutex, 0);
    memset(&act, 0, sizeof (struct sigaction));
    memset(&alarmSig, 0, sizeof (struct sigaction));
    sigemptyset(&act.sa_mask);
    sigemptyset(&alarmSig.sa_mask);
    act.sa_sigaction = sigint_handler;
    alarmSig.sa_sigaction = sigalarm_handler;
    act.sa_flags = SA_SIGINFO;
    alarmSig.sa_flags = SA_SIGINFO;
    if (-1 == sigaction(SIGINT, &act, NULL)) {
        perror("sigaction()");
        exit(EXIT_FAILURE);
    }
    if (-1 == sigaction(SIGALRM, &alarmSig, NULL)) {
        perror("sigaction()");
        exit(EXIT_FAILURE);
    }

    printf("Service started.\n");

    char* conf_file = "config/uiimd.yml";
    if (argc >= 2) {
        conf_file = argv[1];
    }
    FILE *fh = fopen(conf_file, "r");
    uiimconf *conf = parse_yaml_conf(fh);
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;

    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    } else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof (servaddr));

    // assign IP, PORT 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = conf->ADDRESS;
    servaddr.sin_port = htons(conf->PORT);

    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (SA*) & servaddr, sizeof (servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    } else {
        printf("Socket successfully binded..\n");
    }
    // Now server is ready to listen and verification 
    if ((listen(sockfd, MAX_CLIENTS)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    } else {
        printf("Server listening..\n");
    }

    len = sizeof (cli);

    pthread_create(&disThread, NULL, distributerThread, dis);
    // Accept the data packet from client and verification 
    while (dis->run) {
        //alarm(60);
        connfd = accept(sockfd, (SA*) & cli, &len);
#ifndef WHEELFEEDER
        if (connfd < 0) {
            printf("server acccept failed...\n");
            exit(0);
        } else {
            Session *ses = create_session(&sesHead, connfd, conf);
            if (ses == NULL) {
                close(connfd);
                continue;
            } else {
                fcntl(connfd, F_SETFL, O_NONBLOCK); //ich weiss nicht wie ich das sonst machen sollte.
                //int rc = pthread_create(&ses->threadID, NULL, startThread, ses);
                int rc = pthread_create(&(ses->threadID), NULL, startThread, ses);
            }
        }
#endif
#ifdef WHEELFEEDER
        if (connfd < 0) {
            //printf("server acccept failed...\n");
        } else {
            aquireDistributionLock(dis);
            Session *ses = wfCreateSession(dis, connfd, conf);
            releaseDistributionLock(dis);
            pthread_create(&ses->threadID_r, 0, processNewMessagesT, ses);
            printf("%u\n", ses->threadID_r);
        }
#endif
    }
    close(sockfd);
}


