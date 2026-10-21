/* Observe completed CmdItem parsing. No native send calls or disk/network I/O.
 * DLL and trampolines remain pinned until process exit, including after stop.
 * Only payloads whose AddMsg.FromUserName field equals the configured room are
 * published. Python validates the remaining fields before trusting messages.
 */
#define _WIN32_WINNT 0x0600
#include "native_receiver.h"
#include "MinHook.h"
#include <string.h>
#include <wchar.h>
__declspec(dllexport) ReceiveState receive_state={.magic=RECV_MAGIC};
__declspec(dllexport) ReceiveSlot receive_slots[RECV_SLOTS];
__declspec(dllexport) ReceiveCommand receive_commands[32];
static SRWLOCK capture_lock=SRWLOCK_INIT, command_lock=SRWLOCK_INIT;
static ReceiveConfig config;
static ReceiveTarget original;
static uintptr_t command_vtable, buffer_vtable;
static void *hook_target;
static volatile LONG started;
static uint64_t publish_number;

static BOOL read_local(uintptr_t address,void *out,SIZE_T length) {
    SIZE_T copied=0;
    if (address<65536 || !length || length>RECV_LIMIT) return FALSE;
    BOOL ok=ReadProcessMemory(GetCurrentProcess(),(const void *)address,out,length,&copied);
    if (!ok || copied!=length) { InterlockedIncrement64(&receive_state.read_errors);return FALSE; }
    return TRUE;
}
static BOOL contains(const unsigned char *p,size_t n,const char *text) {
    size_t m=strlen(text);
    if (!m || m>n) return FALSE;
    for (size_t i=0;i<=n-m;i++) if (p[i]==(unsigned char)text[0] && !memcmp(p+i,text,m)) return TRUE;
    return FALSE;
}
static BOOL get_varint(const unsigned char *p,size_t n,size_t *at,uint64_t *value) {
    *value=0;
    for (unsigned shift=0;shift<70;shift+=7) {
        if (*at>=n) return FALSE;
        unsigned char b=p[(*at)++];
        if (shift==63 && b>1) return FALSE;
        *value|=(uint64_t)(b&127)<<shift;
        if (!(b&128)) return TRUE;
    }
    return FALSE;
}
static BOOL bytes_field(const unsigned char *p,size_t n,unsigned wanted,const unsigned char **out,size_t *length) {
    size_t at=0;BOOL found=FALSE;
    for (unsigned count=0;at<n && count<256;count++) {
        uint64_t tag=0,value=0;
        if (!get_varint(p,n,&at,&tag) || !(tag>>3) || (tag>>3)>=0x20000000) return FALSE;
        unsigned wire=(unsigned)(tag&7);
        if (wire==0) { if (!get_varint(p,n,&at,&value)) return FALSE; }
        else if (wire==2) {
            if (!get_varint(p,n,&at,&value) || value>n-at) return FALSE;
            if ((tag>>3)==wanted) {
                if (found) return FALSE;
                found=TRUE;*out=p+at;*length=(size_t)value;
            }
            at+=(size_t)value;
        } else if (wire==1 || wire==5) {
            size_t size=wire==1?8:4;if (size>n-at) return FALSE;at+=size;
        } else return FALSE;
    }
    return at==n && found;
}
static BOOL target_room(const unsigned char *p,size_t n) {
    const unsigned char *nested=NULL,*name=NULL;size_t nested_length=0,name_length=0;
    if (!bytes_field(p,n,2,&nested,&nested_length) || !bytes_field(nested,nested_length,1,&name,&name_length)) return FALSE;
    return name_length==strlen(config.room) && !memcmp(name,config.room,name_length);
}
static void record_command(uint32_t id) {
    if (!TryAcquireSRWLockExclusive(&command_lock)) return;
    for (size_t i=0;i<32;i++) {
        ReceiveCommand *item=&receive_commands[i];
        if (item->ready && item->command_id==id) { InterlockedIncrement64(&item->hits);break; }
        if (!item->ready) {
            item->command_id=id;item->hits=1;MemoryBarrier();InterlockedExchange(&item->ready,1);break;
        }
    }
    ReleaseSRWLockExclusive(&command_lock);
}
static void observe(uintptr_t object) {
    uintptr_t vptr=0,buffer=0,string=0,pointer=0;
    uint32_t id=0,declared=0;
    unsigned char header[32],payload[RECV_LIMIT];uint64_t length=0,capacity=0;
    if (!read_local(object,&vptr,8) || vptr!=command_vtable) return;
    if (!read_local(object+0x10,&id,4)) return;
    record_command(id);
    if (!read_local(object+8,&buffer,8) || !buffer) return;
    if (!read_local(buffer,&vptr,8) || vptr!=buffer_vtable) return;
    if (!read_local(buffer+8,&string,8) || !string || !read_local(buffer+0x10,&declared,4)) return;
    if (!read_local(string,header,32)) return;
    memcpy(&length,header+16,8);memcpy(&capacity,header+24,8);
    if (!length || length!=declared || length>capacity) return;
    if (length>RECV_LIMIT) { InterlockedIncrement64(&receive_state.oversize);return; }
    if (capacity<16) {
        if (capacity!=15 || length>15) return;
        memcpy(payload,header,(size_t)length);
    } else {
        memcpy(&pointer,header,8);
        if (!read_local(pointer,payload,(SIZE_T)length)) return;
    }
    if (!target_room(payload,(size_t)length)) return;
    InterlockedIncrement64(&receive_state.room_matches);
    BOOL marker_found=contains(payload,(size_t)length,config.marker);
    if (marker_found) InterlockedIncrement64(&receive_state.marker_matches);
    if (config.marker[0] && !marker_found) return;
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {
        InterlockedIncrement64(&receive_state.dropped);return;
    }
    /* Keep stopped captures frozen, including callbacks finishing after stop. */
    if (receive_state.phase==2) {
        uint64_t number=++publish_number;
        ReceiveSlot *slot=&receive_slots[(number-1)%RECV_SLOTS];
        InterlockedExchange64(&slot->sequence,(LONG64)(number*2-1));
        slot->command_id=id;slot->length=(uint32_t)length;
        slot->thread_id=GetCurrentThreadId();slot->captured_ms=GetTickCount64();
        memcpy(slot->payload,payload,(size_t)length);
        MemoryBarrier();InterlockedExchange64(&slot->sequence,(LONG64)(number*2));
        InterlockedIncrement64(&receive_state.captured);
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
static unsigned char detour(void *object,void *stream) {
    InterlockedIncrement64(&receive_state.calls);
    unsigned char result=original(object,stream);
    DWORD error=GetLastError();
    if (result) {
        InterlockedIncrement64(&receive_state.succeeded);
        if (receive_state.phase==2) observe((uintptr_t)object);
    }
    SetLastError(error);return result;
}
__declspec(dllexport) DWORD WINAPI StopReceive(void *unused) {
    (void)unused;
    LONG phase=InterlockedCompareExchange(&receive_state.phase,4,2);
    if (phase==3) return 0;
    if (phase!=2) return 13;
    MH_STATUS status=MH_DisableHook(hook_target);
    if (status!=MH_OK) { receive_state.phase=-400-status;return 11; }
    InterlockedExchange(&receive_state.phase,3);InterlockedExchange(&started,2);return 0;
}
__declspec(dllexport) DWORD WINAPI RunReceive(void *argument) {
    ReceiveConfig cfg;HMODULE pinned=NULL,host=NULL;void *target=NULL;
    unsigned char actual[24];MH_STATUS status;
    static const unsigned char entry[24]={0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53,0x48,0x83,0xec,0x38,0x48,0x8d,0x6c,0x24,0x30,0x48,0xc7,0x45};
    if (!read_local((uintptr_t)argument,&cfg,sizeof(cfg)) || cfg.magic!=RECV_MAGIC || cfg.fixture>1 ||
        !memchr(cfg.room,0,sizeof(cfg.room)) || !memchr(cfg.marker,0,sizeof(cfg.marker))) return 1;
    size_t n=strlen(cfg.room),m=strlen(cfg.marker);
    if (n<10 || n>127 || strcmp(cfg.room+n-9,"@chatroom") || (m && m<4) || m>63) return 2;
    for (size_t i=0;i<n-9;i++) if (cfg.room[i]<'0' || cfg.room[i]>'9') return 2;
    LONG before=InterlockedCompareExchange(&started,1,0);
    if (before!=0) {
        if (before!=2 || InterlockedCompareExchange(&started,1,2)!=2) return 3;
        if (cfg.fixture!=config.fixture || strcmp(cfg.room,config.room) || strcmp(cfg.marker,config.marker)) {
            InterlockedExchange(&started,2);return 12;
        }
        InterlockedExchange(&receive_state.phase,1);goto enable;
    }
    InterlockedExchange(&receive_state.phase,1);
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)(uintptr_t)&RunReceive,&pinned)) { receive_state.phase=-1;return 4; }
    if (cfg.fixture) {
        wchar_t path[32768];host=GetModuleHandleW(NULL);
        if (!GetModuleFileNameW(host,path,32768)) { receive_state.phase=-2;return 5; }
        wchar_t *name=wcsrchr(path,L'\\');name=name?name+1:path;
        if (wcscmp(name,L"wx-receive-fixture.exe")) { receive_state.phase=-2;return 5; }
        target=(void *)(uintptr_t)GetProcAddress(host,"fixture_parse");
        command_vtable=(uintptr_t)GetProcAddress(host,"fixture_command_vtable");
        buffer_vtable=(uintptr_t)GetProcAddress(host,"fixture_buffer_vtable");
        if (!target || !command_vtable || !buffer_vtable) { receive_state.phase=-2;return 5; }
    } else {
        host=GetModuleHandleW(L"Weixin.dll");
        if (!host) { receive_state.phase=-3;return 6; }
        target=(void *)((uintptr_t)host+0x2e7caf0);
        command_vtable=(uintptr_t)host+0x93d3c78;buffer_vtable=(uintptr_t)host+0x8e3d058;
        if (!read_local((uintptr_t)target,actual,sizeof(actual)) || memcmp(actual,entry,sizeof(entry))) {
            receive_state.phase=-4;return 7;
        }
    }
    memcpy(&config,&cfg,sizeof(cfg));
    status=MH_Initialize();if (status!=MH_OK) { receive_state.phase=-100-status;return 8; }
    status=MH_CreateHook(target,(void *)(uintptr_t)&detour,(void **)&original);
    if (status!=MH_OK) { receive_state.phase=-200-status;return 9; }
    hook_target=target;
enable:
    status=MH_EnableHook(hook_target);
    if (status!=MH_OK) { receive_state.phase=-300-status;return 10; }
    InterlockedExchange(&receive_state.phase,2);return 0;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID unused) {
    (void)unused;if (reason==DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);return TRUE;
}
