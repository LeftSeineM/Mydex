/* Authorized local SQLCipher research. No disk/network I/O or native DB calls.
 * Fixed provider callback only. Bounded private slots; Python authenticates
 * against the explicitly selected history files before accepting any material.
 */
#define _WIN32_WINNT 0x0600
#include "native_key_observer.h"
#include "MinHook.h"
#include <string.h>
#include <wchar.h>
__declspec(dllexport) KeyState key_state={.magic=KEY_MAGIC};
__declspec(dllexport) KeySlot key_slots[64];
static KeyTarget original;
static SRWLOCK lock=SRWLOCK_INIT;
static volatile LONG started;
static uint32_t fixture_mode;
static void *hook_target;
static BOOL read_local(uintptr_t address,void *out,SIZE_T size) {
    SIZE_T done=0;
    if (address<65536 || !size || size>256) return FALSE;
    BOOL ok=ReadProcessMemory(GetCurrentProcess(),(const void *)address,out,size,&done);
    if (!ok || done!=size) { InterlockedIncrement64(&key_state.read_errors);return FALSE; }
    return TRUE;
}
static int detour(void *ctx,int mode,const unsigned char *key,int size,const unsigned char *iv,
                  const unsigned char *in,int length,unsigned char *out) {
    DWORD error=GetLastError();InterlockedIncrement64(&key_state.calls);
    unsigned char candidate[32];
    if (key_state.phase==2 && size==32 && (mode==0 || mode==1) && read_local((uintptr_t)key,candidate,32)) {
        if (TryAcquireSRWLockExclusive(&lock)) {
            if (key_state.phase==2) for (size_t i=0;i<64;i++) {
                KeySlot *slot=&key_slots[i];
                if (slot->ready && !memcmp(slot->key,candidate,32)) break;
                if (!slot->ready) {
                    memcpy(slot->key,candidate,32);MemoryBarrier();InterlockedExchange(&slot->ready,1);
                    InterlockedIncrement64(&key_state.unique_keys);break;
                }
                if (i==63) InterlockedIncrement64(&key_state.dropped);
            }
            ReleaseSRWLockExclusive(&lock);
        } else InterlockedIncrement64(&key_state.dropped);
    }
    SecureZeroMemory(candidate,sizeof(candidate));SetLastError(error);
    return original(ctx,mode,key,size,iv,in,length,out);
}
__declspec(dllexport) DWORD WINAPI StopKeys(void *unused) {
    (void)unused;
    LONG phase=InterlockedCompareExchange(&key_state.phase,4,2);
    if (phase==3) return 0;
    if (phase!=2) return 13;
    MH_STATUS status=MH_DisableHook(hook_target);
    if (status!=MH_OK) { key_state.phase=-400-status;return 11; }
    AcquireSRWLockExclusive(&lock);
    SecureZeroMemory(key_slots,sizeof(key_slots));
    ReleaseSRWLockExclusive(&lock);
    InterlockedExchange(&key_state.phase,3);InterlockedExchange(&started,2);return 0;
}
__declspec(dllexport) DWORD WINAPI RunKeys(void *argument) {
    KeyConfig cfg;HMODULE pinned=NULL,host=NULL;void *target=NULL;
    MH_STATUS status;unsigned char actual[24];
    static const unsigned char entry[24]={0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xec,0x48,0x4c,0x89,0xc7,0x89,0xd3,0x49,0x89,0xce,0x48,0x8b,0x05,0xd8,0x9c,0x88,0x05};
    if (!read_local((uintptr_t)argument,&cfg,sizeof(cfg)) || cfg.magic!=KEY_MAGIC || cfg.fixture>1) return 1;
    LONG before=InterlockedCompareExchange(&started,1,0);
    if (before) {
        if (before!=2 || InterlockedCompareExchange(&started,1,2)!=2) return 3;
        if (cfg.fixture!=fixture_mode) { InterlockedExchange(&started,2);return 12; }
        InterlockedExchange(&key_state.phase,1);goto enable;
    }
    InterlockedExchange(&key_state.phase,1);
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)(uintptr_t)&RunKeys,&pinned)) { key_state.phase=-1;return 4; }
    if (cfg.fixture) {
        wchar_t path[32768];host=GetModuleHandleW(NULL);
        if (!GetModuleFileNameW(host,path,32768)) { key_state.phase=-2;return 5; }
        wchar_t *name=wcsrchr(path,L'\\');name=name?name+1:path;
        if (wcscmp(name,L"wx-key-fixture.exe")) { key_state.phase=-2;return 5; }
        target=(void *)(uintptr_t)GetProcAddress(host,"fixture_cipher");
        if (!target) { key_state.phase=-2;return 5; }
    } else {
        host=GetModuleHandleW(L"Weixin.dll");
        if (!host) { key_state.phase=-3;return 6; }
        target=(void *)((uintptr_t)host+0x58325d0);
        if (!read_local((uintptr_t)target,actual,sizeof(actual)) || memcmp(actual,entry,24)) { key_state.phase=-4;return 7; }
    }
    fixture_mode=cfg.fixture;hook_target=target;
    status=MH_Initialize();if (status!=MH_OK) { key_state.phase=-100-status;return 8; }
    status=MH_CreateHook(target,(void *)(uintptr_t)&detour,(void **)&original);
    if (status!=MH_OK) { key_state.phase=-200-status;return 9; }
enable:
    status=MH_EnableHook(hook_target);
    if (status!=MH_OK) { key_state.phase=-300-status;return 10; }
    InterlockedExchange(&key_state.phase,2);return 0;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID unused) {
    (void)unused;if (reason==DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);return TRUE;
}
