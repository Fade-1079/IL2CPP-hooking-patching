# IL2CPP-hooking-patching
Can be used in pretty much every il2cpp game, somewhat reliable and quite good!


usage:
```#include "patch.h"

Patch pExample;

void EnableBool() {
    BYTE bTrue = 1;
    pExample.Apply((void*)0x842323, &bTrue, sizeof(bTrue));
}

void DisableBool() {
    pExample.Remove();
}
 ```

1 = true 
0 = false
(for booleans)
