//
// Created by darya.nekryach on 2/13/2019.
//

#ifndef LOG_HELPER_H
#define LOG_HELPER_H

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/portnox/dstr.h>

void log_portnox(int code, dstr *message, int priority, REQUEST* req);
void log_portnox_info(dstr *message,  REQUEST* req);
void log_portnox_error(int code, dstr *message, REQUEST* req);

int radius_internal_logger_centrale(int error_code, char *message, REQUEST *request);

#endif //LOG_HELPER_H
