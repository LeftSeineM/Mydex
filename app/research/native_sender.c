/* Fixed-build asynchronous text wrapper. No hooks, secrets or file/network API.
 * It uses the client's allocator for its MSVC strings and a separately owned
 * refcounted callback box; every callback function stays pinned until exit.
 * Native return/callback state is not proof of server delivery.
 */
#include "native_sender.h"
#include <stddef.h>
#include <string.h>
#include <wchar.h>
_Static_assert(sizeof(NativeString)==32,"MSVC string layout");
_Static_assert(offsetof(OnceBox,invoke)==8,"Once callback invocation");
_Static_assert(offsetof(OnceBox,destroy)==16,"Once callback release");
__declspec(dllexport) SendState send_state={.magic=SEND_MAGIC};
static volatile LONG busy;
static char bound_room[128];

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
__declspec(dllexport) DWORD WINAPI RunSend(void *parameter) {
    SendConfig cfg; HMODULE pinned=NULL,host=NULL; uintptr_t base;
    if (!read_local(parameter,&cfg,sizeof(cfg)) || cfg.magic!=SEND_MAGIC || cfg.fixture>1 ||
        !memchr(cfg.room,0,sizeof(cfg.room)) || !memchr(cfg.body,0,sizeof(cfg.body))) return 1;
    size_t length=strlen(cfg.body);
    if (!room_valid(cfg.room) || !length || length>3072 ||
        !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,cfg.body,(int)length,NULL,0)) return 2;
    if (InterlockedCompareExchange(&busy,1,0)!=0) return 3;
    DWORD code=0;TextWrapper wrapper=NULL;ClientNew allocate=NULL;ClientDelete release=NULL;
    TextRequest request={0};NativeString source={0};OnceBox *callback=NULL;
    if (bound_room[0] && strcmp(bound_room,cfg.room)) {code=4;goto done;}
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)(uintptr_t)&RunSend,&pinned)) {code=5;goto done;}
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
    if (!bound_room[0]) strcpy(bound_room,cfg.room);
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
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved) {
    (void)reserved;if (reason==DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);return TRUE;
}
