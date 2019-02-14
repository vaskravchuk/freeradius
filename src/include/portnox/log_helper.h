//
// Created by darya.nekryach on 2/13/2019.
//

#ifndef LOG_HELPER_H
#define LOG_HELPER_H

#include <freeradius-devel/radiusd.h>

void log_p(char* code, char* message, char* priority, REQUEST* req);
void log_info_p(char* message,  REQUEST* req);
void log_error_p(char* code, char* message, REQUEST* req);

int radius_internal_logger_centrale(char* error_code, char* message, REQUEST *request);
#endif //LOG_HELPER_H
