# SandBuster
Anti Sandbox Wrapper To Detect Sandboxes Such as Sandboxie, Cuckoo, Sunbelt, AnyRun, Hybrid-analysis, LastLine, Comodo, Avg, etc. 

## Usage

Simply inlcude it in your project with:
```
#include "sandbuster.h"
```

To kickstart all modules, You have to first supply it with your process name. If you intend to run it as sandbuster.exe, then specify the name like the below example:

```
LPCSTR lpwProcName = L"sandbuster.exe";
```

The run all the modules like the below line:

```
SandbusterKickStarter(lpwProcName, NULL);
```

## Capabilities

__Sandboxes:__
- [x] Sandboxie
- [x] Cuckoo
- [x] Lastline
- [x] Comodo
- [x] AVG
- [x] Sunbelt
- [x] Any.Run
- [x] Hybrid-Analysis
- [x] Windbg
- [x] HyperV
- [x] QEMU
- [x] Generic

