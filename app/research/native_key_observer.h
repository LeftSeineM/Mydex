#ifndef WX_KEY_OBSERVER_H
#define WX_KEY_OBSERVER_H
#include <windows.h>
#include <stdint.h>
#define KEY_MAGIC 0x574b5031U
typedef struct { uint32_t magic,fixture; } KeyConfig;
typedef struct { uint32_t magic;volatile LONG phase;volatile LONG64 calls,unique_keys,read_errors,dropped; } KeyState;
typedef struct { volatile LONG ready;uint32_t reserved;unsigned char key[32]; } KeySlot;
typedef int (*KeyTarget)(void *,int,const unsigned char *,int,const unsigned char *,const unsigned char *,int,unsigned char *);
#endif
