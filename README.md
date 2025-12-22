# Universal-hooking/patching
Can be used in pretty much every il2cpp game, somewhat reliable and quite good!


usage:
```#include "patch.h"

Patch Example;

//Change RVA to ur one
void EnableBool() {
    BYTE bTrue = 1;
    Example.Apply((void*)0x842323, &bTrue, sizeof(bTrue));
}

void DisableBool() {
    Example.Remove();
}
 ```

1 = true 
0 = false
(for booleans)
