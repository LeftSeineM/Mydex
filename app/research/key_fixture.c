#define _WIN32_WINNT 0x0600
#define __USE_MINGW_ANSI_STDIO 1
#include "native_key_observer.h"
#include <string.h>
#include <stdio.h>
static volatile LONG64 bad_results;
static ULONGLONG deadline;
__declspec(dllexport) __attribute__((noinline)) int fixture_cipher(void *ctx,int mode,const unsigned char *key,
    int size,const unsigned char *iv,const unsigned char *in,int length,unsigned char *out) {
    if (ctx!=(void *)0x12345678 || mode<0 || mode>1 || (size!=16 && size!=32) || iv[0]!=11 || length!=96)
        InterlockedIncrement64(&bad_results);
    for (int i=0;i<length;i++) out[i]=in[i]^key[i%size];
    SetLastError(0x4567);return 100+mode;
}
static DWORD WINAPI worker(void *argument) {
    uintptr_t index=(uintptr_t)argument;unsigned char key[32],iv[16]={11},in[96],out[96];
    memset(key,index%2?0x4b:0x51,32);memset(in,0x32,96);
    int size=index<6?32:16,mode=(int)(index%2);
    KeyTarget volatile invoke=fixture_cipher;
    while (GetTickCount64()<deadline) {
        SetLastError(0x9876);
        int result=invoke((void *)0x12345678,mode,key,size,iv,in,96,out);
        if (result!=100+mode || GetLastError()!=0x4567 || out[95]!=(unsigned char)(in[95]^key[95%size]))
            InterlockedIncrement64(&bad_results);
        Sleep(1);
    }
    return 0;
}
int main(void) {
    HANDLE threads[8];deadline=GetTickCount64()+10000;
    for (uintptr_t i=0;i<8;i++) { threads[i]=CreateThread(NULL,0,worker,(void *)i,0,NULL);if (!threads[i]) return 4; }
    printf("ready\n");fflush(stdout);
    if (WaitForMultipleObjects(8,threads,TRUE,13000)!=WAIT_OBJECT_0) return 5;
    for (size_t i=0;i<8;i++) CloseHandle(threads[i]);
    printf("{\"completed\":true,\"bad_results\":%lld}\n",bad_results);return bad_results?6:0;
}
