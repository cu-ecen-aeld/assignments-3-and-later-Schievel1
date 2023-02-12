#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)
int msleep(long msec)
{
    struct timespec ts;
    if (msec < 0) {
        return -1;
    }
    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;
    return nanosleep(&ts, &ts);
}

void* threadfunc(void* thread_param)
{
    struct thread_data* thread_func_args = (struct thread_data *)thread_param;
    msleep(thread_func_args->wait_to_obtain_ms);
    int lock_ret = pthread_mutex_lock(thread_func_args->mut);
    if (lock_ret) {
        thread_func_args->thread_complete_success = false;
        ERROR_LOG("failed to obtain mutex in thread no %u", thread_func_args->thread_number);
        return thread_func_args;
    }
    msleep(thread_func_args->wait_to_release);
    int rel_ret = pthread_mutex_unlock(thread_func_args->mut);
    if (rel_ret) {
        thread_func_args->thread_complete_success = false;
        ERROR_LOG("failed to release mutex in thread no %u", thread_func_args->thread_number);
        return thread_func_args;
    }
    thread_func_args->thread_complete_success = true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    static int thread_number = 0;
    struct thread_data *theThreadData = calloc(1, sizeof(struct thread_data));
    theThreadData->thread_number = thread_number++;
    theThreadData->wait_to_obtain_ms = wait_to_obtain_ms;
    theThreadData->wait_to_release = wait_to_release_ms;
    theThreadData->mut = mutex;
    int ret = pthread_create(thread, NULL, threadfunc, theThreadData);
    return ret? false : true;
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
}
