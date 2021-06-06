/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file mtsl.c
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 2020-06-25
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */
#include <string.h>

#include "mtsl.h"

ListRoot *listRootInit() {
    ListRoot *root = malloc(sizeof (ListRoot));
    root->first = NULL;
    root->tail = NULL;
    root->lock = 0;
    root->count = 0;
    return root;
}

bool listAdd(ListRoot *root, ELEMENT_MTSL *add) {
    aquireLock(root);
    ListElement *ele = malloc(sizeof (ListElement));
    memset(ele, 0, sizeof (ListElement));
    ele->value = add;
    ele->next = NULL;
    if (isEmpty(root)) {
        root->first = ele;
        root->tail = ele;
    } else {
        root->tail->next = ele;
        root->tail = ele;
    }
    ++root->count;
    releaseLock(root);
    return true;
}

bool concatAndClearAdded(ListRoot *root, ListRoot *add) {
    aquireLock(add);
    aquireLock(root);
    if (root->first == NULL) {
        root->first = add->first;
        root->tail = add->tail;
        root->count = add->count;
        add->first = NULL;
        add->tail = NULL;
        add->count = 0;
    } else if (add->first != NULL) {
        root->tail->next = add->first;
        add->first = NULL;
        root->tail = add->tail;
        add->tail = NULL;
        root->count += add->count;
        add->count = 0;
    }
    releaseLock(add);
    releaseLock(root);
    return true;
}

bool remove(ListRoot *root, ELEMENT_MTSL *remove) {
    aquireLock(root);
    if (isEmpty(root)) {
        releaseLock(root);
        return false;
    }
    if (root->first->value == remove) {
        ListElement *tmp = root->first;
        root->first = root->first->next;
        free(tmp);
        --root->count;
        releaseLock(root);
        return true;
    } else {
        ListElement *tmp = root->first->next;
        ListElement *prev = root->first;
        while (tmp != NULL) {
            if (tmp->value == remove) {
                prev->next = tmp->next;
                tmp->next = NULL;
                free(tmp);
                --root->count;
                releaseLock(root);
                return true;
            } else {
                prev = tmp;
                tmp = tmp->next;
            }
        }
        releaseLock(root);
        return false;

    }
}

bool isEmpty(ListRoot *root) {
    return __sync_bool_compare_and_swap(&(root->count), 0, 0);
}

ELEMENT_MTSL *get(ListRoot *root, int pos) {
    aquireLock(root);
    if (isEmpty(root)) {
        releaseLock(root);
        return NULL;
    }
    int count = 0;
    ListElement *tmp = root->first;
    while (tmp != NULL) {
        if (count == pos) {
            releaseLock(root);
            return tmp->value;
        }
        count++;
        tmp = tmp->next;
    }
    releaseLock(root);
    return NULL;

}

ELEMENT_MTSL **toArrayAndRemove(ListRoot *root, int *size) {
    aquireLock(root);
     if (isEmpty(root)) {
        return NULL;
    }
    void **array = calloc(root->count, sizeof (ELEMENT_MTSL*));
    ListElement *tmp = root->first;
    ListElement *toFree = NULL;
    int count = 0;
    while (tmp != NULL) {
        array[count++] = tmp->value;
        toFree = tmp;
        tmp = tmp->next;
        free(toFree);
    }
    root->first = NULL;
    root->tail = NULL;
    __sync_lock_test_and_set(size, count);
    releaseLock(root);
    return array;
}

int MTSLSize(ListRoot *root) {
    return root->count;
}

bool aquireLock(ListRoot *root) {
    while (__sync_lock_test_and_set(&root->lock, 1) == 1);
    return true;
}

bool releaseLock(ListRoot *root) {
    __sync_lock_release(&root->lock);
    return true;
}