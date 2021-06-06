/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file mtsl_types.h
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 2020-06-25
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

/* 
 * File:   mtsl_types.h
 * Author: Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *
 * Created on 25. Juni 2020, 09:41
 */

#ifndef MTSL_H
#define MTSL_H

#include <stdlib.h>
#include <stdbool.h>
#define INIT_SIZE 5
#ifndef ELEMENT_MTSL
#define ELEMENT_MTSL void
#endif

typedef struct listElement {
    ELEMENT_MTSL *value;
    struct listElement *next;
} ListElement;

typedef struct listRoot {
    volatile size_t count;
    volatile int lock;
    ListElement *first;
    ListElement *tail;
} ListRoot;



#ifdef __cplusplus
extern "C" {
#endif
    /**
     * Appends the specified element to the end of this list. The next pointer will be set to NULL!
     * @param root - root list
     * @param add - element to be appended to this list
     * @return true if this list changed as a result of the call
     */
    bool listAdd(ListRoot *root, ELEMENT_MTSL *add);
    /**
     * Concat the both lists 
     * @param root
     * @param add
     * @return true if this list changed as a result of the call
     */
    bool concatAndClearAdded(ListRoot *root, ListRoot *add);
    /**
     * Removes the given element from the List.
     * @param root - the ListRoot from which the element should be removed.
     * @param remove - the element that shoule be removed.
     * @return true if this list changed as a result of the call
     */
    bool listRemove(ListRoot *root, ELEMENT_MTSL *remove);
    /**
     * Removes all elements in the given list;
     * @param root - the ListRoot from which the elements should be removed.
     * @return true if this list changed as a result of the call
     */
    bool listRemoveAll(ListRoot *root);
    /**
     * Check if list empty.
     * @param root - The root that should be tested.
     * @return true if is empty else false.
     */
    bool isEmpty(ListRoot *root);
    /**
     * Returns the element on the given position.
     * @param root - the ListRoot from which the elements should be obtained.
     * @param pos - pos on which element should return;
     * @return the element on the given position
     */
    ELEMENT_MTSL *get(ListRoot *root, int pos);
    /**
     * Creates an Array with all elements in the list and removes them from the list.
     * @param root - the ListRoot from which the elements should be obtained.
     * @param size - size of the list will be set into the given pointer of int.
     * @return ptr to array of elements
     */
    ELEMENT_MTSL **toArrayAndRemove(ListRoot *root, int *size);
    /**
     * Calculates size of list.
     * @param root - list of which the size should be calculated.
     * @return size if given list.
     */
    int MTSLSize(ListRoot *root);
    /**
     * Aquire lock of given list.
     * @param root - given list.
     * @return true if the locks is obtained.
     */
    bool aquireLock(ListRoot *root);
    /**
     * Releases the lock of the given list.
     * @param root - given list
     * @return true
     */
    bool releaseLock(ListRoot *root);

    ListRoot *listRootInit();



#ifdef __cplusplus
}
#endif

#endif /* MTSL_H */

