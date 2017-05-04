#include "hook.cy.h"

void* lookup_symbol(char* libraryname,char* symbolname)
{
    void *imagehandle = dlopen(libraryname, RTLD_GLOBAL | RTLD_NOW);
    if (imagehandle != NULL){
        void * sym = dlsym(imagehandle, symbolname);
        if (sym != NULL){
            return sym;
        }
        else{
            LOGI("(lookup_symbol) dlsym didn't work");
            return NULL;
        }
    }
    else{
        LOGI("(lookup_symbol) dlerror: %s",dlerror());
        return NULL;
    }
}

void * get_base_of_lib_from_maps(char *soname)
{
    void *imagehandle = dlopen(soname, RTLD_LOCAL | RTLD_LAZY);
    if (soname == NULL)
        return NULL;
    if (imagehandle == NULL){
        return NULL;
    }
    uintptr_t * irc = NULL;
    FILE *f = NULL;
    char line[200] = {0};
    char *state = NULL;
    char *tok = NULL;
    char * baseAddr = NULL;
    if ((f = fopen("/proc/self/maps", "r")) == NULL)
        return NULL;
    while (fgets(line, 199, f) != NULL)
    {
        tok = strtok_r(line, "-", &state);
        baseAddr = tok;
        tok = strtok_r(NULL, "\t ", &state);
        tok = strtok_r(NULL, "\t ", &state); // "r-xp" field
        tok = strtok_r(NULL, "\t ", &state); // "0000000" field
        tok = strtok_r(NULL, "\t ", &state); // "01:02" field
        tok = strtok_r(NULL, "\t ", &state); // "133224" field
        tok = strtok_r(NULL, "\t ", &state); // path field

        if (tok != NULL) {
            int i;
            for (i = (int)strlen(tok)-1; i >= 0; --i) {
                if (!(tok[i] == ' ' || tok[i] == '\r' || tok[i] == '\n' || tok[i] == '\t'))
                    break;
                tok[i] = 0;
            }
            {
                size_t toklen = strlen(tok);
                size_t solen = strlen(soname);
                if (toklen > 0) {
                    if (toklen >= solen && strcmp(tok + (toklen - solen), soname) == 0) {
                        fclose(f);
                        return (uintptr_t*)strtoll(baseAddr,NULL,16);
                    }
                }
            }
        }
    }
    fclose(f);
    return NULL;
}

void * get_base_of_lib_from_soinfo(char *soname)
{
    if (soname == NULL)
        return NULL;
    void *imagehandle = dlopen(soname, RTLD_LOCAL | RTLD_LAZY);
    if (imagehandle == NULL){
        return NULL;
    }
    char *basename;
    char *searchname;
    int i;
    void * libdl_ptr=dlopen("libdl.so",3);
    basename = strrchr(soname,'/');
    searchname = basename ? basename +1 : soname;
    for(i =(int) libdl_ptr; i!=NULL; i=*(int*)(i+164)){
        if(!strcmp(searchname,(char*)i)){
            unsigned int *lbase= (unsigned int*)i+140;
            void * baseaddr = (void*)*lbase;
            return baseaddr;
        }
    }
    return NULL;

}

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
    //void * getAgeSym = lookup_symbol("/data/app-lib/com.killer.targetapp-1/libtargetLib.so", "getAge");
    void* libBase = get_base_of_lib_from_maps("/data/app-lib/com.killer.targetapp-1/libtargetLib.so");
    LOGD("libBase is %x.\n", libBase);
    if (libBase)
    {
        void * getAgeSym = libBase + 0xD81;
        LOGD("Hook getAge.\n");
        cigi_hook(getAgeSym, (void *)replaced_getAge, (void**)&original_getAge);
    }
    cigi_hook((void *)arc4random,(void*)&replaced_arc4random,(void**)&original_arc4random);


}