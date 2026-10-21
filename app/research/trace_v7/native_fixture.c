/* Own process only. Exercises the same ABI, exact-marker filter and DLL lifetime. */
#define _WIN32_WINNT 0x0600
#define __USE_MINGW_ANSI_STDIO 1
#include "native_observer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

__declspec(dllexport) uintptr_t fixture_vtable[8];
static volatile LONG64 calls, bad_results;
static ULONGLONG deadline;
static DWORD worker_delay;

__declspec(dllexport) __attribute__((noinline)) uintptr_t fixture_send(void *manager,void *result,const void *pair) {
    if (manager!=(void *)0x12345678 || !pair) InterlockedIncrement64(&bad_results);
    *(uintptr_t *)result=0x10203040;
    InterlockedIncrement64(&calls);
    return (uintptr_t)result;
}

static void set_sso(unsigned char *p,const char *s) {
    uint64_t size=strlen(s),cap=15;
    memcpy(p,s,(size_t)size); memcpy(p+16,&size,8); memcpy(p+24,&cap,8);
}
static DWORD WINAPI worker(void *argument) {
    uintptr_t index=(uintptr_t)argument;
    unsigned char object[0x798]={0}; uintptr_t vptr=(uintptr_t)fixture_vtable;
    memcpy(object,&vptr,8); uint32_t type=1; memcpy(object+0x118,&type,4);
    set_sso(object+0xb0,"123456@chatroom");
    set_sso(object+0x758,index%2?"WXPAIR1006":"WRONG_MARKER");
    uintptr_t wrapper[5]={0x1234,0,0,(uintptr_t)object,0};
    uintptr_t pair[2]={index>=4?(uintptr_t)wrapper:(uintptr_t)object,0};
    LabTarget volatile invoke=fixture_send;
    while (GetTickCount64()<deadline) {
        uintptr_t result=0;
        SetLastError(0x4567);
        uintptr_t returned=invoke((void *)0x12345678,&result,pair);
        if (returned!=(uintptr_t)&result || result!=0x10203040 || GetLastError()!=0x4567)
            InterlockedIncrement64(&bad_results);
        Sleep(worker_delay);
    }
    return 0;
}
int main(int argc,char **argv) {
    if (argc!=2) return 1;
    if (!strcmp(argv[1],"--remote")) {
        worker_delay=1;
        HANDLE threads[8]; deadline=GetTickCount64()+20000;
        for (uintptr_t i=0;i<8;i++) {
            threads[i]=CreateThread(NULL,0,worker,(void *)i,0,NULL);
            if (!threads[i]) return 4;
        }
        printf("ready\n"); fflush(stdout);
        if (WaitForMultipleObjects(8,threads,TRUE,25000)!=WAIT_OBJECT_0) return 5;
        for (int i=0;i<8;i++) CloseHandle(threads[i]);
        printf("{\"completed\":true,\"bad_results\":%lld}\n",bad_results);
        return bad_results?6:0;
    }
    HMODULE dll=LoadLibraryA(argv[1]); if (!dll) return 2;
    LabRun run=(LabRun)(uintptr_t)GetProcAddress(dll,"RunProbe");
    LabState *state=(LabState *)(uintptr_t)GetProcAddress(dll,"lab_state");
    if (!run || !state) return 3;
    LabConfig cfg={.magic=LAB_MAGIC,.seconds=3,.fixture=1,.marker="WXPAIR1006",.target_room="123456@chatroom"};
    HANDLE threads[8]; deadline=GetTickCount64()+7000;
    for (uintptr_t i=0;i<8;i++) {
        threads[i]=CreateThread(NULL,0,worker,(void *)i,0,NULL);
        if (!threads[i]) return 4;
    }
    Sleep(200);
    DWORD code=run(&cfg);
    /* Drop caller's reference while workers continue: DLL must stay pinned. */
    FreeLibrary(dll);
    strcpy(cfg.marker,"OTHER_MARKER");
    DWORD rejected=run(&cfg);
    strcpy(cfg.marker,"WXPAIR1006"); cfg.seconds=2;
    LONG64 first_calls=state->calls;
    DWORD second_code=run(&cfg);
    if (WaitForMultipleObjects(8,threads,TRUE,10000)!=WAIT_OBJECT_0) return 5;
    for (int i=0;i<8;i++) CloseHandle(threads[i]);
    BOOL passed=code==0 && second_code==0 && rejected==12 && state->phase==3 && state->calls>first_calls && state->calls>100 && state->matches>0 &&
        state->matches<state->calls && state->room_ready && strcmp(state->room,"123456@chatroom")==0 &&
        bad_results==0 && calls>state->calls && state->read_errors==0;
    printf("{\"passed\":%s,\"exit_status\":%lu,\"phase\":%ld,\"observed\":%lld,\"matches\":%lld,\"total_calls\":%lld,\"bad_results\":%lld,\"read_errors\":%lld}\n",
        passed?"true":"false",code,state->phase,state->calls,state->matches,calls,bad_results,state->read_errors);
    return passed?0:6;
}
