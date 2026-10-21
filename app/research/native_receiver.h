#ifndef WX_LAB_RECEIVER_H
#define WX_LAB_RECEIVER_H
#include <windows.h>
#include <stdint.h>
#define RECV_MAGIC 0x57524331U
#define RECV_LIMIT 16384
#define RECV_SLOTS 16
typedef struct {
    uint32_t magic, fixture;
    char room[128], marker[64];
} ReceiveConfig;
typedef struct {
    uint32_t magic;
    volatile LONG phase;
    volatile LONG64 calls, succeeded, read_errors, room_matches;
    volatile LONG64 marker_matches, captured, dropped, oversize;
} ReceiveState;
typedef struct {
    volatile LONG64 sequence; /* odd while being written, even when published */
    uint32_t command_id, length, thread_id, reserved;
    uint64_t captured_ms;
    unsigned char payload[RECV_LIMIT];
} ReceiveSlot;
typedef struct {
    volatile LONG ready;
    uint32_t command_id;
    volatile LONG64 hits;
} ReceiveCommand;
typedef unsigned char (*ReceiveTarget)(void *,void *);
#endif
