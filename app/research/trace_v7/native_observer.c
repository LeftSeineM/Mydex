/* Passive exact-marker observer. No send calls, credentials, network, or files.
 * A hook DOES patch executable memory; this is not the external read-only tool.
 * The module and trampoline stay allocated until process exit to avoid unload
 * races with callbacks already in flight. Re-arming reuses that same hook and
 * the same immutable marker; it never removes/recreates a trampoline.
 */
#define _WIN32_WINNT 0x0600
#include "native_observer.h"
#include "MinHook.h"
#include <string.h>
#include <wchar.h>

__declspec(dllexport) LabState lab_state = {.magic=LAB_MAGIC};
__declspec(dllexport) LabShape lab_shapes[16];
__declspec(dllexport) LabTextDiagnostic lab_text_diagnostics[16];
__declspec(dllexport) LabTrace lab_traces[4];
static SRWLOCK trace_lock=SRWLOCK_INIT;
static char target_room[128];
static SRWLOCK shape_lock=SRWLOCK_INIT;
static SRWLOCK diagnostic_lock=SRWLOCK_INIT;
static LabTarget original;
static uintptr_t module_base, expected_vtable;
static char marker[64];
static size_t marker_size;
static volatile LONG started, room_claimed;
static void *hook_target;
static DWORD configured_fixture;
static size_t module_size;

__declspec(dllexport) DWORD WINAPI StopProbe(void *unused) {
    (void)unused;
    LONG phase=InterlockedCompareExchange(&lab_state.phase,4,2);
    if (phase==3) return 0;
    if (phase!=2) return 13;
    MH_STATUS status=MH_DisableHook(hook_target);
    if (status!=MH_OK) { lab_state.phase=-400-status; return 11; }
    /* Callbacks already in flight keep their valid code and trampoline. */
    InterlockedExchange(&lab_state.phase,3);
    InterlockedExchange(&started,2);
    return 0;
}

static BOOL read_local(uintptr_t address, void *buffer, SIZE_T length) {
    SIZE_T copied=0;
    if (address<65536 || length>256) return FALSE;
    BOOL ok=ReadProcessMemory(GetCurrentProcess(),(const void *)address,buffer,length,&copied);
    if (!ok || copied!=length) { InterlockedIncrement64(&lab_state.read_errors); return FALSE; }
    return TRUE;
}

static BOOL string_value(uintptr_t address, char *out, size_t cap, size_t expected) {
    unsigned char header[32]; uint64_t length, capacity, pointer;
    if (!read_local(address,header,sizeof(header))) return FALSE;
    memcpy(&length,header+16,8); memcpy(&capacity,header+24,8);
    if (length>=cap || capacity<length || capacity>1048576 || (expected && length!=expected)) return FALSE;
    if (capacity<16) {
        if (capacity!=15 || length>15) return FALSE;
        memcpy(out,header,(size_t)length);
    } else {
        memcpy(&pointer,header,8);
        if (length && !read_local((uintptr_t)pointer,out,(SIZE_T)length)) return FALSE;
    }
    out[length]=0; return TRUE;
}

static void record_diagnostic(const LabTextDiagnostic *value) {
    if (!TryAcquireSRWLockExclusive(&diagnostic_lock)) return;
    for (size_t i=0;i<16;i++) {
        LabTextDiagnostic *s=&lab_text_diagnostics[i];
        if (s->ready && !memcmp((const char *)s+8,(const char *)value+8,sizeof(*s)-8)) {
            InterlockedIncrement(&s->hits);break;
        }
        if (!s->ready) {
            memcpy((char *)s+8,(const char *)value+8,sizeof(*s)-8);s->hits=1;
            MemoryBarrier();InterlockedExchange(&s->ready,1);break;
        }
    }
    ReleaseSRWLockExclusive(&diagnostic_lock);
}

static void record_trace(void) {
    if (!TryAcquireSRWLockExclusive(&trace_lock)) return;
    void *frames[32]={0}; uint64_t rvas[24]={0}; DWORD count=0;
    USHORT n=CaptureStackBackTrace(1,32,frames,NULL);
    for (USHORT i=0;i<n && count<24;i++) {
        uintptr_t p=(uintptr_t)frames[i];
        if (p>=module_base && p<module_base+module_size) rvas[count++]=p-module_base;
    }
    if (count) for (size_t i=0;i<4;i++) {
        LabTrace *s=&lab_traces[i];
        if (s->ready && s->count==count && !memcmp(s->rvas,rvas,count*8)) {
            InterlockedIncrement(&s->hits); break;
        }
        if (!s->ready) {
            s->count=count;s->thread_id=GetCurrentThreadId();
            memcpy(s->rvas,rvas,count*8);s->hits=1;
            MemoryBarrier();InterlockedExchange(&s->ready,1);break;
        }
    }
    ReleaseSRWLockExclusive(&trace_lock);
}

static void inspect_object(uintptr_t object) {
    uintptr_t vtable; uint32_t type; char body[64], room[128];
    if (!read_local(object,&vtable,8)) return;
    if (vtable!=expected_vtable) return;
    LabTextDiagnostic diagnostic={0}; unsigned char header[32];
    if (read_local(object+0x118,&type,4)) diagnostic.type_value=type;
    if (read_local(object+0x758,header,32)) {
        memcpy(&diagnostic.body_length,header+16,8);memcpy(&diagnostic.body_capacity,header+24,8);
    }
    if (read_local(object+0xb0,header,32)) {
        memcpy(&diagnostic.room_length,header+16,8);memcpy(&diagnostic.room_capacity,header+24,8);
    }
    diagnostic.body_exact=string_value(object+0x758,body,sizeof(body),marker_size) && !memcmp(body,marker,marker_size);
    if (string_value(object+0xb0,room,sizeof(room),0)) {
        size_t n=strlen(room);
        diagnostic.room_kind=n>=9 && !strcmp(room+n-9,"@chatroom")?1:2;
    }
    diagnostic.stage=diagnostic.type_value!=1?1:!diagnostic.body_exact?2:diagnostic.room_kind!=1?3:4;
    record_diagnostic(&diagnostic);
    if (diagnostic.type_value==1 && diagnostic.room_kind==1 && !strcmp(room,target_room)) record_trace();
    if (!read_local(object+0x118,&type,4) || type!=1) return;
    if (!string_value(object+0x758,body,sizeof(body),marker_size) || memcmp(body,marker,marker_size)) return;
    if (!string_value(object+0xb0,room,sizeof(room),0)) return;
    size_t size=strlen(room);
    if (size<10 || strcmp(room+size-9,"@chatroom")) return;
    for (size_t i=0;i<size-9;i++) if (room[i]<'0' || room[i]>'9') return;
    InterlockedIncrement64(&lab_state.matches);
    if (InterlockedCompareExchange(&room_claimed,1,0)==0) {
        memcpy(lab_state.room,room,size+1);
        lab_state.vtable_rva=vtable-module_base;
        lab_state.thread_id=GetCurrentThreadId();
        MemoryBarrier(); InterlockedExchange(&lab_state.room_ready,1);
    }
}

static uint64_t vtable_rva(uintptr_t object) {
    uintptr_t vptr=0;
    if (object<65536 || !read_local(object,&vptr,8)) return 0;
    return vptr>=module_base && vptr<module_base+module_size ? vptr-module_base : 0;
}

static void record_shape(uintptr_t object,uintptr_t child8,uintptr_t child18) {
    uint64_t a=vtable_rva(object),b=vtable_rva(child8),c=vtable_rva(child18);
    if (!TryAcquireSRWLockExclusive(&shape_lock)) return;
    for (size_t i=0;i<16;i++) {
        LabShape *s=&lab_shapes[i];
        if (s->ready && s->root_vtable_rva==a && s->child8_vtable_rva==b && s->child18_vtable_rva==c) {
            InterlockedIncrement(&s->hits);break;
        }
        if (!s->ready) {
            s->root_vtable_rva=a;s->child8_vtable_rva=b;s->child18_vtable_rva=c;s->hits=1;
            MemoryBarrier();InterlockedExchange(&s->ready,1);break;
        }
    }
    ReleaseSRWLockExclusive(&shape_lock);
}

static void observe(const void *pair) {
    uintptr_t object,vtable,child8=0,child18=0;
    if (!read_local((uintptr_t)pair,&object,8) || !read_local(object,&vtable,8)) return;
    if (vtable==expected_vtable) { record_shape(object,0,0);inspect_object(object); return; }
    /* Stage A receives a shared operation/task, not necessarily a text object.
     * Static code shows shared objects at +0x18; task constructor also has +8.
     * These remain candidates. Only a recognized text vtable + exact marker is
     * allowed through; no arbitrary message body is retained.
     */
    read_local(object+8,&child8,8);read_local(object+0x18,&child18,8);
    record_shape(object,child8,child18);
    if (child8>=65536 && child8!=object) inspect_object(child8);
    if (child18>=65536 && child18!=object) inspect_object(child18);
}

static uintptr_t detour(void *manager, void *result, const void *pair) {
    DWORD error=GetLastError();
    InterlockedIncrement64(&lab_state.calls);
    observe(pair);
    SetLastError(error);
    return original(manager,result,pair);
}

__declspec(dllexport) DWORD WINAPI RunProbe(void *parameter) {
    LabConfig cfg; unsigned char actual[24]; HMODULE pinned=NULL; void *target=NULL;
    MH_STATUS status;
    static const unsigned char entry[24]={0x55,0x41,0x57,0x41,0x56,0x56,0x57,0x53,0x48,0x81,0xec,0x68,0x03,0x00,0x00,0x48,0x8d,0xac,0x24,0x80,0x00,0x00,0x00,0x0f};
    if (!read_local((uintptr_t)parameter,&cfg,sizeof(cfg)) || cfg.magic!=LAB_MAGIC ||
        cfg.seconds>120 || cfg.fixture>1 || !memchr(cfg.marker,0,sizeof(cfg.marker)) || !memchr(cfg.target_room,0,sizeof(cfg.target_room))) return 1;
    size_t length=strlen(cfg.marker);
    if (length<4 || length>63) return 2;
    LONG previous=InterlockedCompareExchange(&started,1,0);
    if (previous!=0) {
        if (previous!=2 || InterlockedCompareExchange(&started,1,2)!=2) return 3;
        if (cfg.fixture!=configured_fixture || strcmp(cfg.marker,marker) || strcmp(cfg.target_room,target_room)) {
            InterlockedExchange(&started,2); return 12;
        }
        target=hook_target;
        InterlockedExchange(&lab_state.phase,1);
        goto enable_existing;
    }
    InterlockedExchange(&lab_state.phase,1);
    /* Pin before installing. Never execute hook setup under DllMain's loader lock. */
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)(uintptr_t)&RunProbe,&pinned)) { lab_state.phase=-1; return 4; }
    if (cfg.fixture) {
        HMODULE host=GetModuleHandleW(NULL); wchar_t path[32768];
        if (!GetModuleFileNameW(host,path,32768)) { lab_state.phase=-2; return 5; }
        wchar_t *name=wcsrchr(path,L'\\'); name=name?name+1:path;
        if (wcscmp(name,L"wx-native-fixture.exe")) { lab_state.phase=-2; return 5; }
        module_base=(uintptr_t)host;
        target=(void *)(uintptr_t)GetProcAddress(host,"fixture_send");
        expected_vtable=(uintptr_t)GetProcAddress(host,"fixture_vtable");
        if (!target || !expected_vtable) { lab_state.phase=-2; return 5; }
    } else {
        HMODULE host=GetModuleHandleW(L"Weixin.dll");
        if (!host) { lab_state.phase=-3; return 6; }
        module_base=(uintptr_t)host; target=(void *)(module_base+0x17f3750);
        expected_vtable=module_base+0x8e53588;
        if (!read_local((uintptr_t)target,actual,sizeof(actual)) || memcmp(entry,actual,sizeof(entry))) {
            lab_state.phase=-4; return 7;
        }
    }
    IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)module_base;
    IMAGE_NT_HEADERS64 *nt=(IMAGE_NT_HEADERS64 *)(module_base+dos->e_lfanew);
    module_size=nt->OptionalHeader.SizeOfImage;
    memcpy(marker,cfg.marker,length+1); marker_size=length;
    memcpy(target_room,cfg.target_room,strlen(cfg.target_room)+1);
    configured_fixture=cfg.fixture;
    status=MH_Initialize();
    if (status!=MH_OK) { lab_state.phase=-100-status; return 8; }
    status=MH_CreateHook(target,(void *)(uintptr_t)&detour,(void **)&original);
    if (status!=MH_OK) { lab_state.phase=-200-status; return 9; }
    hook_target=target;
enable_existing:
    status=MH_EnableHook(target);
    if (status!=MH_OK) { lab_state.phase=-300-status; return 10; }
    InterlockedExchange(&lab_state.phase,2);
    /* Continuous mode has no sleeping worker thread and no expiration timer. */
    if (cfg.seconds==0) return 0;
    ULONGLONG deadline=GetTickCount64()+cfg.seconds*1000ULL;
    while (GetTickCount64()<deadline && lab_state.phase==2) Sleep(25);
    return StopProbe(NULL);
}

BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved) {
    (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
