#ifndef WX_NATIVE_SENDER_H
#define WX_NATIVE_SENDER_H
#include <windows.h>
#include <stdint.h>
#define SEND_MAGIC 0x57535031U
typedef struct { DWORD magic,fixture; char room[128],body[4096]; } SendConfig;
typedef struct { char data[16]; uint64_t length,capacity; } NativeString;
typedef struct { NativeString room,body; } TextRequest;
typedef struct OnceBox OnceBox;
struct OnceBox { volatile LONG references; DWORD padding;
    void (*invoke)(OnceBox *,const void *); void (*destroy)(OnceBox *); };
typedef struct { DWORD magic; volatile LONG phase; volatile LONG64 submissions,callbacks,disposed;
    DWORD callback_tag,thread_id; } SendState;
typedef void (*TextWrapper)(void *,const TextRequest *,const NativeString *,OnceBox **);
typedef void *(*ClientNew)(size_t);
typedef void (*ClientDelete)(void *,size_t);
#endif
