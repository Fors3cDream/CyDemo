#include "hook.cy.h"



void cigi_hook(void *orig_fcn, void* new_fcn, void **orig_fcn_ptr)
{
    MSHookFunction(orig_fcn, new_fcn, orig_fcn_ptr);
}

MSConfig(MSFilterExecutable, "/system/bin/app_process")

int (*original_arc4random)(void);
int replaced_arc4random(void)
{
    return 1234;
}

int (*original_getAge)(void);
int replaced_getAge(void)
{
    return 28;
}

// 如果symbolName在so中未设置为导出，则可以通过获取到在文件中的偏移值 + baseAddr的方式进行hook
void* lookup_symbol(char* libraryName, char* symbolName)
{
    void *imageHandle = dlopen(libraryName, RTLD_NOW | RTLD_GLOBAL);

    if(imageHandle != NULL)
    {
        void *sym = dlsym(imageHandle, symbolName);
        if(sym != NULL) {
            return sym;
        }
        else {
            LOGI("(lookup_symbol) dlsym didn't work successfully!\n");
            return NULL;
        }
    }
    else {
        LOGI("(lookup_symbol) dlerror: %s\n", dlerror());
        return NULL;
    }
}

MSInitialize {
    LOGD("Substarte hook initialize.\n");
    void * getAgeSym = lookup_symbol("/data/app-lib/com.killer.targetapp-1/libtargetLib.so", "getAge");
    if (getAgeSym)
    {
        LOGD("Hook getAge.\n");
        cigi_hook(getAgeSym, (void *)replaced_getAge, (void**)&original_getAge);
    }
    cigi_hook((void *)arc4random,(void*)&replaced_arc4random,(void**)&original_arc4random);


}