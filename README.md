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

Function `void SandbusterKickStarter(LPCSTR lpProcName, LPCSTR OnlineCheck)` can be modified to only contain the neccessary modules. You can also remove the strings:
 ```
 if (SandboxieDetect())
		printf("\n\t[-] Local Test Done. SandBoxie Is Present.\n");
	else
		printf("\n\t[+] Local Test Done. Something Went Wrong, Probably No Sandboxie Is Present.\n");


	if (!WMIExec())
		printf("\n\t[-] AnyRun Is Present.");
	else
		printf("\n\t[+] AnyRun Sandbox Wasnt Found.\n");


	if (VerifyNameAlter(lpProcName))
		printf("\n\t[+] Process Names Wasnt Subject To Alterations.");
	else
		printf("\n\t[-] Process Names Was Altered.");


	if (CheckMacAddress(_T("\x12\xa9\x86")))
		printf("\n\n\t[-] Mac Address Is Suspicious. AnyRun Sandbox Is Present.");
	else
		printf("\n\n\t[+] No Suspicious Mac Address Related To Anyrun Was Found.");

	if (CheckMacAddress(_T("\x9a\x2a\x81")))
		printf("\n\n\t[-] Mac Address Is Suspicious. Hybrid-Analysis Sandbox Is Present.");
	else
		printf("\n\n\t[+] No Suspicious Mac Address Related To HybridAnalysis Was Found.");



	if (DetectAltSandbox())
		printf("\n\n\t[-] Injected Sandbox DLL Detected.");
	else
		printf("\n\n\t[+] No Injected DLL Was Found.");


	if (UserNameCheck())
		printf("\n\n\t[-] Sandbox Username Detected.");
	else
		printf("\n\n\t[+] No Suspicious Username Detected.");


	//Aggresive Checks, Do Not Use These Modules If You Knowingly Intend To Use Your Payload In a VM Environment.
	if (AggressiveHyperVCheck())
		printf("\n\n\t[-] HyperV Presence Is Detected.\n\n");
	else
		printf("\n\n\t[+] No HyperV Presence Yet!\n\n");


	CuckooMemoryArtifact(&found);
	if (!found)
		printf("\n\n\t[+] No Memory Artifact Found. Cuckoo Is not Present.\n\n");
	else
		printf("\n\n\t[-] Cuckoo Memory Artifact Detected.\n\n");
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

