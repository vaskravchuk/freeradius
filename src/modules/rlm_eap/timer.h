/*
 * thread.h    Header file containing the interfaces for posix timers.
 */

#include <pthread.h>

typedef struct {
    int interval;           /* timer tick interval in microseconds */
    pthread_t thread;       /* posix thread handler */
    void(*action)(void*);   /* action to call */ 
    void *user_data         /* user data for action */ 
} timer_info;


/*
 * Timer handler
 */
typedef timer_info* ptimer_t;

/*
 * Create new timer that begin after interval delay
 * Should be freed by free_timer
 * interval = timer interval in seconds
 * action = method to tick by timer
 */
ptimer_t create_timer(double interval, void action(void*), void *user_data);

/*
 * Free timer
 */
void free_timer(ptimer_t timer);