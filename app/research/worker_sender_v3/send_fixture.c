/* Isolated ABI/ownership test with synchronous and delayed callback delivery. */
#include "native_sender.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static volatile LONG bad,allocations;static DWORD tls_index;
__declspec(dllexport) uintptr_t fixture_message_vtable[8];
__declspec(dllexport) BOOL fixture_context_valid(void) {return TlsGetValue(tls_index)==(void *)0x4142;}
__declspec(dllexport) __attribute__((noinline)) uintptr_t fixture_core(void *manager,void *result,const void *pair,uint32_t flag) {
    if (manager!=(void *)0x1234 || !pair || flag!=1) InterlockedIncrement(&bad);
    *(uintptr_t *)result=0x5555;return (uintptr_t)result;
}
__declspec(dllexport) __attribute__((noinline)) uintptr_t fixture_pump(void *task) {(void)task;return 0x6060;}
static DWORD WINAPI worker(void *argument) {
    (void)argument;TlsSetValue(tls_index,(void *)0x4142);
    unsigned char object[0x798]={0};uintptr_t vptr=(uintptr_t)fixture_message_vtable;
    memcpy(object,&vptr,8);NativeString room={.length=15,.capacity=15};strcpy(room.data,"123456@chatroom");memcpy(object+0xb0,&room,32);
    uintptr_t pair[2]={(uintptr_t)object,0};
    typedef uintptr_t (*CorePointer)(void *,void *,const void *,uint32_t);
    typedef uintptr_t (*PumpPointer)(void *);
    CorePointer volatile core=fixture_core;PumpPointer volatile pump=fixture_pump;
    ULONGLONG end=GetTickCount64()+6000;
    while (GetTickCount64()<end) {
        uintptr_t result=0;SetLastError(0x4545);
        uintptr_t returned=core((void *)0x1234,&result,pair,1);
        if (returned!=(uintptr_t)&result || result!=0x5555 || GetLastError()!=0x4545 || pump(NULL)!=0x6060) InterlockedIncrement(&bad);
        Sleep(50);
    }
    return 0;
}
__declspec(dllexport) void *fixture_new(size_t count) {InterlockedIncrement(&allocations);return malloc(count);}
__declspec(dllexport) void fixture_delete(void *pointer,size_t count) {(void)count;free(pointer);InterlockedDecrement(&allocations);}
static const char *value(const NativeString *s) {const char *p=s->data;if (s->capacity>=16) memcpy(&p,s->data,8);return p;}
static DWORD WINAPI delayed(void *argument) {
    OnceBox *box=argument;Sleep(120);unsigned char result[64]={1};box->invoke(box,result);
    if (InterlockedDecrement(&box->references)==0) box->destroy(box);
    return 0;
}
__declspec(dllexport) void fixture_text(void *unused,const TextRequest *request,const NativeString *source,OnceBox **callback) {
    if (!fixture_context_valid() || unused || !request || !source || !callback || !*callback || (strcmp(value(&request->room),"123456@chatroom") && strcmp(value(&request->room),"654321@chatroom")) ||
        strlen(value(&request->body))!=request->body.length || source->length || (*callback)->references!=1) InterlockedIncrement(&bad);
    OnceBox *box=*callback;*callback=NULL;
    if (request->body.length<=15) {unsigned char result[64]={1};box->invoke(box,result);if (InterlockedDecrement(&box->references)==0) box->destroy(box);}
    else {HANDLE thread=CreateThread(NULL,0,delayed,box,0,NULL);if (!thread) InterlockedIncrement(&bad);else CloseHandle(thread);}
}
int main(void) {
    tls_index=TlsAlloc();HANDLE thread=CreateThread(NULL,0,worker,NULL,0,NULL);
    if (!thread) return 2;
    puts("ready");fflush(stdout);WaitForSingleObject(thread,8000);CloseHandle(thread);TlsFree(tls_index);
    printf("{\"bad\":%ld,\"outstanding_allocations\":%ld}\n",bad,allocations);
    return bad || allocations?1:0;
}
