// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_thread.h"
#include <pthread.h>
#include <errno.h>

static pthread_mutex_t mutex0 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

// Mutex Lock
void CY_Lock(int index)
{
    pthread_mutex_t mutex;
    switch (index) {
        case 0:
            mutex = mutex0;
            break;
        case 1:
            mutex = mutex1;
            break;
        default:
            mutex = mutex0;
            break;
    }
    int rv = pthread_mutex_lock(&mutex);
    if (rv == EOWNERDEAD) {
#ifndef __ANDROID__
        pthread_mutex_consistent(&mutex);
#endif
    }
}

// Mutex Unlock
void CY_UnLock(int index)
{
    pthread_mutex_t mutex;
    switch (index) {
        case 0:
            mutex = mutex0;
            break;
        case 1:
            mutex = mutex1;
            break;
        default:
            mutex = mutex0;
            break;
    }
    pthread_mutex_unlock(&mutex);
}
