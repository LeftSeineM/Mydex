#define _WIN32_WINNT 0x0600
/* Fixed-build asynchronous text wrapper. No hooks, secrets or file/network API.
 * It uses the client's allocator for its MSVC strings and a separately owned
 * refcounted callback box; every callback function stays pinned until exit.
 * Native return/callback state is not proof of server delivery.
 */
#include "native_sender.h"
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <intrin.h>
#include "MinHook.h"
_Static_assert(sizeof(NativeString)==32,"MSVC string layout");
_Static_assert(offsetof(OnceBox,invoke)==8,"Once callback invocation");
_Static_assert(offsetof(OnceBox,destroy)==16,"Once callback release");
__declspec(dllexport) SendState send_state={.magic=SEND_MAGIC};
static volatile LONG busy;


static BOOL read_local(const void *source,void *out,size_t length) {
    SIZE_T count=0;
    return ReadProcessMemory(GetCurrentProcess(),source,out,length,&count) && count==length;
}
static void completed(OnceBox *box,const void *result) {
    (void)box;
    unsigned char tag=255;
    if (result) read_local(result,&tag,1);
    send_state.callback_tag=tag;
    InterlockedIncrement64(&send_state.callbacks);
}
static void disposed(OnceBox *box) {
    InterlockedIncrement64(&send_state.disposed);
    HeapFree(GetProcessHeap(),0,box);
}
static BOOL initialize_string(NativeString *out,const char *text,ClientNew allocate) {
    memset(out,0,sizeof(*out));out->length=strlen(text);out->capacity=15;
    if (out->length<=15) {memcpy(out->data,text,(size_t)out->length+1);return TRUE;}
    out->capacity=out->length|15;
    void *buffer=allocate((size_t)out->capacity+1);
    if (!buffer) return FALSE;
    memcpy(buffer,text,(size_t)out->length+1);memcpy(out->data,&buffer,8);
    return TRUE;
}
static void free_string(NativeString *value,ClientDelete release) {
    if (value->capacity>=16) {
        void *buffer=NULL;memcpy(&buffer,value->data,8);
        if (buffer) release(buffer,(size_t)value->capacity+1);
    }
    memset(value,0,sizeof(*value));
}
static BOOL room_valid(const char *value) {
    size_t n=strlen(value);
    if (n<10 || n>100 || strcmp(value+n-9,"@chatroom")) return FALSE;
    for (size_t i=0;i<n-9;i++) if (value[i]<'0' || value[i]>'9') return FALSE;
    return TRUE;
}
static BOOL allowed_room(const char *room,DWORD fixture) {
    if (fixture) return !strcmp(room,"123456@chatroom") || !strcmp(room,"654321@chatroom") || !strcmp(room,"777777@chatroom") || !strcmp(room,"888888@chatroom");
    return !strcmp(room,"90000000003@chatroom") || !strcmp(room,"90000000008@chatroom") || !strcmp(room,"90000000001@chatroom") || !strcmp(room,"90000000005@chatroom");
}
static DWORD perform_send(void *parameter) {
    SendConfig cfg; HMODULE pinned=NULL,host=NULL; uintptr_t base;
    if (!read_local(parameter,&cfg,sizeof(cfg)) || cfg.magic!=SEND_MAGIC || cfg.fixture>1 ||
        !memchr(cfg.room,0,sizeof(cfg.room)) || !memchr(cfg.body,0,sizeof(cfg.body))) return 1;
    size_t length=strlen(cfg.body);
    if (!room_valid(cfg.room) || !length || length>3072 ||
        !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,cfg.body,(int)length,NULL,0)) return 2;
    if (InterlockedCompareExchange(&busy,1,0)!=0) return 3;
    DWORD code=0;TextWrapper wrapper=NULL;ClientNew allocate=NULL;ClientDelete release=NULL;
    TextRequest request={0};NativeString source={0};OnceBox *callback=NULL;
    if (!allowed_room(cfg.room,cfg.fixture)) {code=4;goto done;}
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)(uintptr_t)&perform_send,&pinned)) {code=5;goto done;}
    if (cfg.fixture) {
        wchar_t path[32768];host=GetModuleHandleW(NULL);
        if (!GetModuleFileNameW(host,path,32768)) {code=6;goto done;}
        wchar_t *name=wcsrchr(path,L'\\');name=name?name+1:path;
        if (wcscmp(name,L"wx-send-fixture.exe")) {code=6;goto done;}
        wrapper=(TextWrapper)(uintptr_t)GetProcAddress(host,"fixture_text");
        allocate=(ClientNew)(uintptr_t)GetProcAddress(host,"fixture_new");
        release=(ClientDelete)(uintptr_t)GetProcAddress(host,"fixture_delete");
        if (!wrapper || !allocate || !release) {code=7;goto done;}
    } else {
        host=GetModuleHandleW(L"Weixin.dll");if (!host) {code=8;goto done;}
        base=(uintptr_t)host;
        unsigned char actual[24];
        static const unsigned char expected[24]={0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xec,0x18,0x03,0x00,0x00,0x48,0x8d,0xac,0x24,0x80};
        if (!read_local((void *)(base+0x54b02f0),actual,24) || memcmp(actual,expected,24)) {code=9;goto done;}
        uintptr_t app=0,vptr=0;
        if (!read_local((void *)(base+0xb912690),&app,8) || !app || !read_local((void *)app,&vptr,8)) {code=10;goto done;}
        IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS64 *nt=(IMAGE_NT_HEADERS64 *)(base+dos->e_lfanew);
        if (vptr<base || vptr>=base+nt->OptionalHeader.SizeOfImage) {code=10;goto done;}
        wrapper=(TextWrapper)(base+0x54b02f0);allocate=(ClientNew)(base+0x74ab89c);release=(ClientDelete)(base+0x74ab8e0);
    }
    if (!initialize_string(&request.room,cfg.room,allocate) ||
        !initialize_string(&request.body,cfg.body,allocate) ||
        !initialize_string(&source,"",allocate)) {code=11;goto cleanup;}
    callback=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*callback));
    if (!callback) {code=12;goto cleanup;}
    callback->references=1;callback->invoke=completed;callback->destroy=disposed;
    
    send_state.thread_id=GetCurrentThreadId();send_state.phase=1;
    InterlockedIncrement64(&send_state.submissions);
    // The wrapper copies its strings and moves the callback into its queued work.
    wrapper(NULL,&request,&source,&callback);
    send_state.phase=2;
    if (callback) {code=13;if (InterlockedDecrement(&callback->references)==0) callback->destroy(callback);}
cleanup:
    free_string(&request.room,release);free_string(&request.body,release);free_string(&source,release);
done:
    if (code) send_state.phase=-(LONG)code;
    InterlockedExchange(&busy,0);return code;
}
typedef uintptr_t (*CoreCall)(void *,void *,const void *,uint32_t);
typedef uintptr_t (*PumpCall)(void *);
typedef struct { DWORD magic; volatile LONG phase,pending; DWORD worker_thread;
    volatile LONG64 core_calls,pump_calls,queued,executed,context_failures;
    DWORD last_code,execution_thread; } WorkerState;
__declspec(dllexport) WorkerState worker_state={.magic=SEND_MAGIC};
static CoreCall core_original;static PumpCall pump_original;
static void *core_target,*pump_target;
static uintptr_t worker_base,worker_vtable;
static DWORD worker_fixture;

static SendConfig queued_config;
static SRWLOCK queue_lock=SRWLOCK_INIT;

static BOOL current_context_valid(void) {
    if (worker_fixture) {
        typedef BOOL (*Check)(void);
        Check check=(Check)(uintptr_t)GetProcAddress(GetModuleHandleW(NULL),"fixture_context_valid");
        return check && check();
    }
    DWORD index=0;uintptr_t vector=(uintptr_t)__readgsqword(0x58),tls=0,weak=0,context=0;
    if (!read_local((void *)(worker_base+0xb9141a0),&index,4) || index>4096 || !vector) return FALSE;
    if (!read_local((void *)(vector+index*8),&tls,8) || !tls) return FALSE;
    if (!read_local((void *)(tls+0x1f0),&weak,8) || !weak) return FALSE;
    return read_local((void *)weak,&context,8) && context!=0;
}
static BOOL target_message(const void *pair) {
    uintptr_t object=0,vptr=0;NativeString room;
    if (!pair || !read_local(pair,&object,8) || !object || !read_local((void *)object,&vptr,8) || vptr!=worker_vtable) return FALSE;
    if (!read_local((void *)(object+0xb0),&room,32) || room.length>100 || room.capacity<room.length) return FALSE;
    char text[128]={0};
    if (room.capacity==15 && room.length<=15) memcpy(text,room.data,(size_t)room.length);
    else if (room.capacity>=16 && room.capacity<=1048576) {
        uintptr_t p=0;memcpy(&p,room.data,8);
        if (!read_local((void *)p,text,(size_t)room.length)) return FALSE;
    } else return FALSE;
    return allowed_room(text,worker_fixture);
}
static void drain(void) {
    if (worker_state.phase!=2 || worker_state.worker_thread!=GetCurrentThreadId() ||
        InterlockedCompareExchange(&worker_state.pending,2,1)!=1) return;
    if (!current_context_valid()) {
        InterlockedIncrement64(&worker_state.context_failures);worker_state.last_code=30;
        InterlockedExchange(&worker_state.pending,0);return;
    }
    worker_state.execution_thread=GetCurrentThreadId();
    worker_state.last_code=perform_send(&queued_config);
    InterlockedIncrement64(&worker_state.executed);
    InterlockedExchange(&worker_state.pending,0);
}
static uintptr_t core_detour(void *manager,void *result,const void *pair,uint32_t flag) {
    DWORD before=GetLastError();BOOL target=target_message(pair);SetLastError(before);
    uintptr_t returned=core_original(manager,result,pair,flag);DWORD after=GetLastError();
    InterlockedIncrement64(&worker_state.core_calls);
    if (target && current_context_valid()) worker_state.worker_thread=GetCurrentThreadId();
    drain();SetLastError(after);return returned;
}
static uintptr_t pump_detour(void *task) {
    uintptr_t returned=pump_original(task);DWORD after=GetLastError();
    InterlockedIncrement64(&worker_state.pump_calls);drain();SetLastError(after);return returned;
}
__declspec(dllexport) DWORD WINAPI StopWorker(void *unused) {
    (void)unused;
    if (worker_state.phase==5) return 0;
    if (worker_state.phase!=2) return 40;
    InterlockedExchange(&worker_state.phase,4);
    InterlockedCompareExchange(&worker_state.pending,0,1);
    MH_STATUS a=MH_DisableHook(core_target),b=MH_DisableHook(pump_target);
    if (a!=MH_OK || b!=MH_OK) {worker_state.phase=-40;return 41;}
    worker_state.phase=5;return 0;
}
__declspec(dllexport) DWORD WINAPI InstallWorker(void *parameter) {
    SendConfig cfg;HMODULE pin=NULL,host=NULL;
    if (!read_local(parameter,&cfg,sizeof(cfg)) || cfg.magic!=SEND_MAGIC || cfg.fixture>1 ||
        !memchr(cfg.room,0,sizeof(cfg.room)) || !room_valid(cfg.room) || !allowed_room(cfg.room,cfg.fixture)) return 1;
    if (InterlockedCompareExchange(&worker_state.phase,1,0)!=0) return 2;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCWSTR)(uintptr_t)&InstallWorker,&pin)) return 3;
    worker_fixture=cfg.fixture;
    if (cfg.fixture) {
        host=GetModuleHandleW(NULL);
        core_target=(void *)(uintptr_t)GetProcAddress(host,"fixture_core");
        pump_target=(void *)(uintptr_t)GetProcAddress(host,"fixture_pump");
        worker_vtable=(uintptr_t)GetProcAddress(host,"fixture_message_vtable");
        if (!core_target || !pump_target || !worker_vtable) return 4;
    } else {
        host=GetModuleHandleW(L"Weixin.dll");if (!host) return 5;worker_base=(uintptr_t)host;
        core_target=(void *)(worker_base+0x178f100);pump_target=(void *)(worker_base+0xd823e0);worker_vtable=worker_base+0x8e53588;
        unsigned char code[24];
        static const unsigned char core_bytes[24]={0x55,0x41,0x57,0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xec,0x78,0x48,0x8d,0x6c,0x24,0x70,0x48,0xc7,0x45,0x00,0xfe,0xff,0xff};
        static const unsigned char pump_bytes[24]={0x55,0x56,0x57,0x48,0x81,0xec,0x70,0x01,0x00,0x00,0x48,0x8d,0xac,0x24,0x80,0x00,0x00,0x00,0x48,0xc7,0x85,0xd8,0x00,0x00};
        if (!read_local(core_target,code,24) || memcmp(code,core_bytes,24) ||
            !read_local(pump_target,code,24) || memcmp(code,pump_bytes,24)) return 6;
    }
    if (MH_Initialize()!=MH_OK || MH_CreateHook(core_target,(void *)(uintptr_t)&core_detour,(void **)&core_original)!=MH_OK ||
        MH_CreateHook(pump_target,(void *)(uintptr_t)&pump_detour,(void **)&pump_original)!=MH_OK) return 7;
    if (MH_EnableHook(core_target)!=MH_OK) return 8;
    if (MH_EnableHook(pump_target)!=MH_OK) {MH_DisableHook(core_target);return 9;}
    worker_state.phase=2;return 0;
}
__declspec(dllexport) DWORD WINAPI AdoptWorker(void *parameter) {
    DWORD cfg[2];
    if (!read_local(parameter,cfg,sizeof(cfg)) || cfg[0]!=SEND_MAGIC || !cfg[1] || worker_state.phase!=2) return 50;
    if (worker_state.worker_thread) return 51;
    worker_state.worker_thread=cfg[1];return 0;
}
__declspec(dllexport) DWORD WINAPI RunSend(void *parameter) {
    SendConfig cfg;
    if (!read_local(parameter,&cfg,sizeof(cfg)) || cfg.magic!=SEND_MAGIC || cfg.fixture!=worker_fixture ||
        !memchr(cfg.room,0,sizeof(cfg.room)) || !memchr(cfg.body,0,sizeof(cfg.body)) ||
        !allowed_room(cfg.room,cfg.fixture) || !strlen(cfg.body) || strlen(cfg.body)>3072 ||
        !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,cfg.body,(int)strlen(cfg.body),NULL,0)) return 10;
    if (worker_state.phase!=2 || !TryAcquireSRWLockExclusive(&queue_lock)) return 11;
    DWORD result=0;
    if (worker_state.pending) result=12;
    else {memcpy(&queued_config,&cfg,sizeof(cfg));MemoryBarrier();InterlockedExchange(&worker_state.pending,1);InterlockedIncrement64(&worker_state.queued);}
    ReleaseSRWLockExclusive(&queue_lock);return result;
}

BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved) {
    (void)reserved;if (reason==DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);return TRUE;
}
