#ifndef _HOOK_CY_H_
#define _HOOK_CY_H_

#include <android/log.h>
#include <substrate.h>

#define LOG_TAG "SUBhook"

#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

void cigi_hook(void *orig_fcn, void* new_fcn, void **orig_fcn_ptr);
void* lookup_symbol(char* libraryName, char* symbolName);

#endif