/*
 * thread.h    Header file containing the interfaces for posix timers.
 */
typedef struct {
    int interval;           /* timer tick interval in microseconds */
    pthread_t thread;       /* posix thread handler */
    void(*action)(void*);   /* action to call */ 
    void *user_data         /* user data for action */ 
} timer_info;


/*
 * Timer handler
 */
typedef timer_info* timer_t;

/*
 * Create new timer that begin after interval delay
 * Should be freed by free_timer
 * interval = timer interval in seconds
 * action = method to tick by timer
 */
timer_t create_timer(double interval, void action(void*), void *user_data);

/*
 * Free timer
 */
void free_timer(timer_t timer);