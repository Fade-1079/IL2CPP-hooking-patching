#include "patch.h"
#include <cstring>

Patch::Patch()
    : addr(nullptr), len(0), applied(false) {
    std::memset(backup, 0, sizeof(backup));
}

bool Patch::ProtectRWX(void* p, size_t s, DWORD& oldProt) {
    return VirtualProtect(p, s, PAGE_EXECUTE_READWRITE, &oldProt) != 0;
}

void Patch::RestoreProt(void* p, size_t s, DWORD oldProt) {
    DWORD tmp;
    VirtualProtect(p, s, oldProt, &tmp);
}

void Patch::FlushIC(void* p, size_t s) {
    FlushInstructionCache(GetCurrentProcess(), p, s);
}

bool Patch::Apply(void* target, const BYTE* bytes, size_t bytesLen) {
    if (!target || !bytes || bytesLen == 0)
        return false;

    addr = target;
    len = bytesLen;

    DWORD old{};
    if (!ProtectRWX(addr, len, old))
        return false;

    std::memcpy(backup, addr, (len <= sizeof(backup)) ? len : sizeof(backup));
    std::memcpy(addr, bytes, len);

    FlushIC(addr, len);
    RestoreProt(addr, len, old);

    applied = Verify(bytes, len);
    return applied;
}

bool Patch::Verify(const BYTE* bytes, size_t bytesLen) const {
    if (!addr || !bytes || bytesLen == 0)
        return false;

    BYTE read[32]{};
    SIZE_T rd{};
    ReadProcessMemory(GetCurrentProcess(), addr, read, bytesLen, &rd);

    return rd == bytesLen && std::memcmp(read, bytes, bytesLen) == 0;
}

bool Patch::Reapply(const BYTE* bytes, size_t bytesLen, int retries, int sleepMs) {
    for (int i = 0; i < retries; ++i) {
        if (Apply(addr, bytes, bytesLen))
            return true;
        Sleep(sleepMs);
    }
    return false;
}

void Patch::Remove() {
    if (!applied || !addr || len == 0)
        return;

    DWORD old{};
    if (!ProtectRWX(addr, len, old))
        return;

    std::memcpy(addr, backup, (len <= sizeof(backup)) ? len : sizeof(backup));
    FlushIC(addr, len);
    RestoreProt(addr, len, old);

    applied = false;
    addr = nullptr;
    len = 0;
    std::memset(backup, 0, sizeof(backup));
}

HMODULE WaitForModule(const char* name, DWORD timeoutMs) {
    DWORD start = GetTickCount();
    HMODULE h = nullptr;

    while ((h = GetModuleHandleA(name)) == nullptr) {
        if (GetTickCount() - start > timeoutMs)
            break;
        Sleep(50);
    }
    return h;
}

bool AddrInModule(HMODULE hMod, void* addr) {
    if (!hMod || !addr)
        return false;

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
        return false;

    BYTE* base = static_cast<BYTE*>(mi.lpBaseOfDll);
    return static_cast<BYTE*>(addr) >= base &&
        static_cast<BYTE*>(addr) < base + mi.SizeOfImage;
}

bool IsExecutable(void* addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;

    DWORD p = mbi.Protect;
    return (p & (PAGE_EXECUTE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY)) != 0;
}
