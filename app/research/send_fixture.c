/* Isolated ABI/ownership test with synchronous and delayed callback delivery. */
#include "native_sender.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static volatile LONG bad,allocations;
__declspec(dllexport) void *fixture_new(size_t count) {InterlockedIncrement(&allocations);return malloc(count);}
__declspec(dllexport) void fixture_delete(void *pointer,size_t count) {(void)count;free(pointer);InterlockedDecrement(&allocations);}
static const char *value(const NativeString *s) {const char *p=s->data;if (s->capacity>=16) memcpy(&p,s->data,8);return p;}
static DWORD WINAPI delayed(void *argument) {
    OnceBox *box=argument;Sleep(120);unsigned char result[64]={1};box->invoke(box,result);
    if (InterlockedDecrement(&box->references)==0) box->destroy(box);
    return 0;
}
__declspec(dllexport) void fixture_text(void *unused,const TextRequest *request,const NativeString *source,OnceBox **callback) {
    if (unused || !request || !source || !callback || !*callback || strcmp(value(&request->room),"123456@chatroom") ||
        strlen(value(&request->body))!=request->body.length || source->length || (*callback)->references!=1) InterlockedIncrement(&bad);
    OnceBox *box=*callback;*callback=NULL;
    if (request->body.length<=15) {unsigned char result[64]={1};box->invoke(box,result);if (InterlockedDecrement(&box->references)==0) box->destroy(box);}
    else {HANDLE thread=CreateThread(NULL,0,delayed,box,0,NULL);if (!thread) InterlockedIncrement(&bad);else CloseHandle(thread);}
}
int main(void) {
    puts("ready");fflush(stdout);Sleep(4000);
    printf("{\"bad\":%ld,\"outstanding_allocations\":%ld}\n",bad,allocations);
    return bad || allocations?1:0;
}
