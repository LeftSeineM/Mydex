/* Own process: post-return parsing, concurrent capture, false/true return and
 * last-error preservation. Five traffic classes exercise both exact filters.
 */
#define _WIN32_WINNT 0x0600
#define __USE_MINGW_ANSI_STDIO 1
#include "native_receiver.h"
#include <string.h>
#include <stdio.h>
__declspec(dllexport) uintptr_t fixture_command_vtable[8],fixture_buffer_vtable[8];
static volatile LONG64 bad_results;
static ULONGLONG deadline;
typedef struct { uintptr_t vtable,buffer;uint32_t id,unused; } Command;
typedef struct { uintptr_t vtable,string;uint32_t length,unused; } Buffer;
typedef struct { unsigned char header[32],payload[512];Buffer buffer;uint32_t mode; } Input;
__declspec(dllexport) __attribute__((noinline)) unsigned char fixture_parse(void *object,void *stream) {
    Command *command=object;Input *input=stream;
    command->vtable=(uintptr_t)fixture_command_vtable;
    command->buffer=(uintptr_t)&input->buffer;
    command->id=input->mode==4?17:5;
    SetLastError(0x4567);
    return input->mode==3?0:1;
}
static void varint(unsigned char *out,size_t *n,uint64_t value) {
    while (value>=128) { out[(*n)++]=(unsigned char)(value|128);value>>=7; }
    out[(*n)++]=(unsigned char)value;
}
static void number(unsigned char *out,size_t *n,unsigned field,uint64_t value) {
    varint(out,n,field*8);varint(out,n,value);
}
static void bytes(unsigned char *out,size_t *n,unsigned field,const unsigned char *p,size_t size) {
    varint(out,n,field*8+2);varint(out,n,size);memcpy(out+*n,p,size);*n+=size;
}
static void text(unsigned char *out,size_t *n,unsigned field,const char *s) {
    unsigned char nested[256];size_t k=0;
    bytes(nested,&k,1,(const unsigned char *)s,strlen(s));bytes(out,n,field,nested,k);
}
static DWORD WINAPI worker(void *argument) {
    uint32_t mode=(uint32_t)(uintptr_t)argument%5;
    Input input={.mode=mode};Command command={0};size_t n=0;
    number(input.payload,&n,1,100);text(input.payload,&n,2,mode==1?"999999@chatroom":"123456@chatroom");
    text(input.payload,&n,3,"wxid_fixture_bot");number(input.payload,&n,4,1);
    text(input.payload,&n,5,mode==2?"wxid_member:\nWRONG_MARKER":"wxid_member:\nWXRECV1006");
    number(input.payload,&n,9,1791280000);number(input.payload,&n,12,123456789012345678ULL);
    uintptr_t pointer=(uintptr_t)input.payload;uint64_t size=n,cap=511;
    memcpy(input.header,&pointer,8);memcpy(input.header+16,&size,8);memcpy(input.header+24,&cap,8);
    input.buffer.vtable=(uintptr_t)fixture_buffer_vtable;
    input.buffer.string=(uintptr_t)input.header;input.buffer.length=(uint32_t)n;
    ReceiveTarget volatile invoke=fixture_parse;
    while (GetTickCount64()<deadline) {
        memset(&command,0,sizeof(command));SetLastError(0x1234);
        unsigned char result=invoke(&command,&input);
        if (result!=(mode==3?0:1) || GetLastError()!=0x4567 || command.buffer!=(uintptr_t)&input.buffer)
            InterlockedIncrement64(&bad_results);
        Sleep(1);
    }
    return 0;
}
int main(void) {
    HANDLE threads[10];deadline=GetTickCount64()+14000;
    for (uintptr_t i=0;i<10;i++) {
        threads[i]=CreateThread(NULL,0,worker,(void *)i,0,NULL);if (!threads[i]) return 4;
    }
    printf("ready\n");fflush(stdout);
    if (WaitForMultipleObjects(10,threads,TRUE,17000)!=WAIT_OBJECT_0) return 5;
    for (size_t i=0;i<10;i++) CloseHandle(threads[i]);
    printf("{\"completed\":true,\"bad_results\":%lld}\n",bad_results);
    return bad_results?6:0;
}
