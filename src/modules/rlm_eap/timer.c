/*
 * thread.c    Posix timers implementation.
 */

#include <timer.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

void timer_tick(void *data)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    timer_info* t_info;
    
    t_info = data;

    /* infinity loop till cancel occured */
    while (1) {
        usleep(t_info->interval);

        /* postpone cancellation to finish main action safety */
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        t_info->action(t_info->user_data);
        /* return cancellation */
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

        /* check if we got cancellation event during main action */
        pthread_testcancel();
    }
}

timer_t create_timer(double interval, void action(void*), void *user_data) {
    /* create timer handler. Wrapper with necessary info */
    timer_info* t_info;
    
    t_info = malloc(sizeof(timer_info));

    /* convert seconds to microseconds */
    t_info->interval = interval*1000000;
    t_info->action = action;
    t_info->user_data = user_data;

    /* create posix thread */
    pthread_create(&(t_info->thread), NULL, timer_tick, t_info);

    return t_info;
}

void free_timer(timer_t timer) {
    int status;

    /* for some optimization issues */
    timer_info* timer_info = timer;

    /* cancel thread */
    pthread_cancel(timer_info->thread);

    /* just in case, wait thread complition */
    pthread_join(timer_info->thread, &status);

    /* free handler */
    free(timer_info);
}