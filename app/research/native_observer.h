#ifndef WX_LAB_OBSERVER_H
#define WX_LAB_OBSERVER_H
#include <windows.h>
#include <stdint.h>
#define LAB_MAGIC 0x574c4231U
typedef struct {
    uint32_t magic, seconds, fixture, reserved;
    char marker[64];
} LabConfig;
typedef struct {
    uint32_t magic;
    volatile LONG phase; /* 0 idle, 1 starting, 2 enabled, 3 disabled, 4 stopping, negative error */
    volatile LONG64 calls, matches, read_errors;
    uint64_t vtable_rva;
    DWORD thread_id;
    volatile LONG room_ready;
    char room[128];
} LabState;
typedef struct {
    volatile LONG ready, hits;
    uint64_t root_vtable_rva, child8_vtable_rva, child18_vtable_rva;
} LabShape;
typedef struct {
    volatile LONG ready,hits;
    uint32_t type_value,stage;
    uint64_t body_length,body_capacity,room_length,room_capacity;
    uint32_t body_exact,room_kind;
} LabTextDiagnostic;
typedef uintptr_t (*LabTarget)(void *, void *, const void *);
typedef DWORD (WINAPI *LabRun)(void *);
#endif
