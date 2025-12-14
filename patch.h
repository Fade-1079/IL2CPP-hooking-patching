#pragma once
#include <windows.h>
#include <Psapi.h>
#include <cstddef>
#include <cstdint>

struct Patch {
    void* addr;
    BYTE   backup[32];
    size_t len;
    bool   applied;

    Patch();

    bool Apply(void* target, const BYTE* bytes, size_t bytesLen);
    bool Verify(const BYTE* bytes, size_t bytesLen) const;
    bool Reapply(const BYTE* bytes, size_t bytesLen, int retries = 5, int sleepMs = 50);
    void Remove();

private:
    static bool ProtectRWX(void* p, size_t s, DWORD& oldProt);
    static void RestoreProt(void* p, size_t s, DWORD oldProt);
    static void FlushIC(void* p, size_t s);
};

HMODULE WaitForModule(const char* name, DWORD timeoutMs);
bool AddrInModule(HMODULE hMod, void* addr);
bool IsExecutable(void* addr);
