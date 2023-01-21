
/*
------------------------------------------------------------

>>>>>>>>>>>>>>> SANDBOX DETECTION WRAPPER <<<<<<<<<<<<<<<

	Usage:
		#include "sandbuster.h"

	Limitations:
		No Hook/Trampoline Detection.

------------------------------------------------------------
*/



#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <tchar.h>
#include <wbemidl.h>
#include "Shlwapi.h"
#include <iphlpapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")

#define _WIN32_WINNT 0x0400
#define _WIN32_DCOM

#define INFO_BUFFER_SIZE 32767

#define SUSP_CTRL_STRING "_CTRL"
#define PAGE_SIZE 4096

#define DATA_SUSP_ENTRY_STRING(instring) {instring SUSP_CTRL_STRING, sizeof(instring) - 1}



//#include <DbgHelp.h>
//#pragma comment (lib, "Dbghelp.lib")



typedef struct
{
	char* data;
	size_t size;
} DATA_ENTRY_t;


BOOL found;



void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}




DWORD GetProcessIdentifier(LPCTSTR ProcessName) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) { // must call this first
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap); // close handle on failure
	return 0;
}





HANDLE ProcessHandle(LPCSTR lpwProcName)
{
	DWORD testval = GetProcessIdentifier(lpwProcName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, testval);
	HANDLE ExhProc = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, testval);

	return hProc;
}



//get external module handle
BOOL GetModuleHandleExternal(HANDLE hProcess, LPCSTR hModuleName)
{
	DWORD cbNeeded, cProcesses;
	HMODULE hMods[64];

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			//if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
				//wprintf(L"\t DLL loaded: %s\n", szModName);

			BOOL test = GetProcAddress(hMods[i], hModuleName);

			if (test)
				return TRUE;
			//printf("\n>>>>>>>> FOUND IT!!!!!! \n");
			//exit(-1);
		//else
			//printf("\n>>>>>Nothing.....\n");
		}
		return FALSE;
	}
}




void* pGetFunctionHandle(char* MyNtdllFunction, PVOID MyDLLBaseAddress)
{
	DWORD j;
	uintptr_t RVA = 0;

	const LPVOID BaseDLLAddr = (LPVOID)MyDLLBaseAddress;

	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)BaseDLLAddr;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseDLLAddr + pImgDOSHead->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseDLLAddr + pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD Address = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfFunctions);
	PDWORD Name = (PDWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNames);
	PWORD Ordinal = (PWORD)((LPBYTE)BaseDLLAddr + pImgExpDir->AddressOfNameOrdinals);

	for (j = 0; j < pImgExpDir->NumberOfNames; j++)
	{
		if (!strcmp(MyNtdllFunction, (char*)BaseDLLAddr + Name[j]))
		{
			RVA = (uintptr_t)((LPBYTE)Address[Ordinal[j]]);
			break;
		}
	}

	if (RVA)
	{
		uintptr_t moduleBase = (uintptr_t)BaseDLLAddr;
		uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + RVA);
		return (PVOID)TrueAddress;
	}
	else
		return (PVOID)RVA;
}




void* FindDllThroughBase(wchar_t* DllName)
{
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
	PVOID DLLAddress = 0;

	PPEB pPeb = 0;

	//64bit
	PPEB pPEB = (PPEB)__readgsqword(0x60);


	// 32bit
	//PPEB pPEB = (PPEB)__readfsword(0x60);


	PPEB_LDR_DATA pLdr = pPEB->Ldr;

	PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY AddressFirstlpNode = AddressFirstPLIST->Flink;

	for (PLIST_ENTRY lpNode = AddressFirstlpNode; lpNode != AddressFirstPLIST; lpNode = lpNode->Flink)
	{
		lpNode--;
		pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)lpNode;

		wchar_t* FullDLLName = (wchar_t*)pDataTableEntry->FullDllName.Buffer;

		for (int size = wcslen(FullDLLName), cpt = 0; cpt < size; cpt++)
			FullDLLName[cpt] = tolower(FullDLLName[cpt]);

		if (wcsstr(FullDLLName, DllName) != NULL)
		{
			DLLAddress = (PVOID)pDataTableEntry->DllBase;
			return DLLAddress;
		}

		lpNode++;
	}

	return DLLAddress;
}




BOOL SandboxieDetect()
{
	wchar_t* DllName = L"sbiedll";
	PCSTR FunctionNameToSearch = "SbieDll_Hook";


	PVOID DLLaddress = FindDllThroughBase(DllName);
	if (DLLaddress)
		printf("\n\tDLL base address of %ls : %x \n", DllName, DLLaddress);
	else
		return FALSE;

	PVOID FunctionAddress = pGetFunctionHandle(FunctionNameToSearch, DLLaddress);
	printf("\taddress of the function %s : %x\n", FunctionNameToSearch, FunctionAddress);

	if (FunctionAddress)
		return TRUE;

	return FALSE;
}




BOOL WMIExec()
{
	HRESULT hr = 0;

	IWbemLocator* locator = NULL;
	IWbemServices* services = NULL;
	IEnumWbemClassObject* results = NULL;

	BSTR resource = SysAllocString(L"ROOT\\CIMV2");
	BSTR language = SysAllocString(L"WQL");
	BSTR query = SysAllocString(L"SELECT * FROM Win32_PortConnector");

	hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

	hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&locator);
	hr = locator->lpVtbl->ConnectServer(locator, resource, NULL, NULL, NULL, 0, NULL, NULL, &services);

	hr = services->lpVtbl->ExecQuery(services, language, query, WBEM_FLAG_BIDIRECTIONAL, NULL, &results);


	if (results != NULL)
	{
		IWbemClassObject* result = NULL;
		ULONG returnedCount = 0;
		unsigned int count = 0;

		while ((hr = results->lpVtbl->Next(results, WBEM_INFINITE, 1, &result, &returnedCount)) == S_OK)
		{
			VARIANT name;
			VARIANT speed;

			hr = result->lpVtbl->Get(result, L"Name", 0, &name, 0, 0);
			hr = result->lpVtbl->Get(result, L"MaxClockSpeed", 0, &speed, 0, 0);

			count++;
			result->lpVtbl->Release(result);
		}

		if (!count)
			return FALSE;
	}
	else
		return FALSE;

	results->lpVtbl->Release(results);
	services->lpVtbl->Release(services);
	locator->lpVtbl->Release(locator);

	CoUninitialize();

	SysFreeString(query);
	SysFreeString(language);
	SysFreeString(resource);

	return TRUE;
}





BOOL VerifyNameAlter(LPCSTR lpwProcName)
{
	LPCSTR lpName;
	TCHAR Buffer[MAX_PATH];

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
	GetModuleFileNameEx(hProc, 0, Buffer, MAX_PATH);
	lpName = PathFindFileName(Buffer);

	int nCmp = lstrcmp(lpwProcName, lpName);

	if (!nCmp)
		return TRUE;
	else
		return FALSE;
}



//mac
//fe80:b9a3:aa8f::3e8e:fe86%11
//12-a9-86-6c-77-de

BOOL CheckMacAddress(const TCHAR* szMac)
{
	BOOL bResult = FALSE;
	PIP_ADAPTER_INFO pAdapterInfo, pAdapterInfoPtr;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	pAdapterInfo = (PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		_tprintf(_T("MALLOC Failed.\n"));
		return -1;
	}

	DWORD dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);

	if (dwResult == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (PIP_ADAPTER_INFO)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL)
		{
			printf("MALLOC Failed.\n");
			return 1;
		}

		dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
	}

	if (dwResult == ERROR_SUCCESS)
	{
		CHAR szMacMultiBytes[4];
		for (int i = 0; i < 4; i++)
			szMacMultiBytes[i] = (CHAR)szMac[i];

		pAdapterInfoPtr = pAdapterInfo;

		while (pAdapterInfoPtr)
		{
			if (pAdapterInfoPtr->AddressLength == 6 && !memcmp(szMacMultiBytes, pAdapterInfoPtr->Address, 3))
			{
				bResult = TRUE;
				break;
			}
			pAdapterInfoPtr = pAdapterInfoPtr->Next;
		}
	}

	free(pAdapterInfo);

	return bResult;
}




BOOL DetectAltSandbox()
{
	LPWSTR DLLNames[] =
	{
		L"cmdvrt32.dll",
		L"cmdvrt64.dll",
		L"dbghelp.dll",
		L"cuckoomon.dll",
		L"pstorec.dll",
		L"avghookx.dll",
		L"avghooka.dll",
		L"snxhk.dll",
		L"api_log.dll",
		L"dir_watch.dll",
		L"wpespy.dll"
	};


	unsigned int IteratorSize = sizeof(DLLNames) / sizeof(DLLNames[0]);
	unsigned int Detection = 0;

	for (unsigned int Iterator = 0; Iterator < IteratorSize; Iterator++)
	{
		PVOID DLLaddress = FindDllThroughBase(DLLNames[Iterator]);

		if (DLLaddress)
			Detection++;
	}


	if (Detection)
		return TRUE;
	else
		return FALSE;
}




BOOL UserNameCheck()
{
	LPSTR names[] =
	{
		L"USER",
		//test ------------------------
		//L"dude",
		//test ------------------------
		L"Anonymous",
		L"ANDY",
		L"COMPUTERNAME",
		L"CUCKOO",
		L"SANDBOX",
		L"NMSDBOX",
		L"MUELLER-PC",
		L"JOHN-PC",
		L"7SILVIA",
		L"HANSPETER-PC",
		L"XXXX-OX",
		L"CWSX",
		L"WILBERT-SC",
		L"XPAMAST-SC"
	};


	LPSTR  infoBuf[INFO_BUFFER_SIZE];
	DWORD  bufCharCount = INFO_BUFFER_SIZE;

	unsigned int Iterator = 0;
	unsigned int IteratorSize = sizeof(names) / sizeof(names[0]);

	BOOL Result = FALSE;


	GetUserName(infoBuf, &bufCharCount);


	for (Iterator = 0; Iterator < IteratorSize; Iterator++)
	{
		if (!lstrcmp(infoBuf, names[Iterator]))
		{
			Result = TRUE;
			break;
		}
	}

	if (Result)
		return TRUE;

	return FALSE;
}




BOOL CuckooMemoryArtifact(BOOL* found)
{
	DATA_ENTRY_t suspicius_data[] =
	{
		DATA_SUSP_ENTRY_STRING("cuckoomon"),
		DATA_SUSP_ENTRY_STRING("New_NtDeleteFile"),
		DATA_SUSP_ENTRY_STRING("retaddr-check"),
		DATA_SUSP_ENTRY_STRING("HookHandle"),
		DATA_SUSP_ENTRY_STRING("nhook detection"),
		DATA_SUSP_ENTRY_STRING("distorm"),
		DATA_SUSP_ENTRY_STRING("capstone"),
		DATA_SUSP_ENTRY_STRING("Cuckoo")
	};

	char* actual_addr = (char*)0;
	int Iterator = 0;
	BOOL found_or_endmemory = FALSE;
	BOOL exception_ex = FALSE;
	*found = FALSE;

	printf("\t[INFO] Searching suspicius data in my memory: ");

	do
	{
		for (int Iterator = 0; Iterator < ARRAYSIZE(suspicius_data); Iterator++)
		{
			__try
			{
				if (actual_addr != suspicius_data[Iterator].data && memcmp(suspicius_data[Iterator].data, actual_addr, suspicius_data[Iterator].size) == 0)
				{
					__try
					{
						if (memcmp(actual_addr + suspicius_data[Iterator].size, SUSP_CTRL_STRING, sizeof(SUSP_CTRL_STRING)) != 0)
						{
							char buff[255];
							memset(buff, 0, sizeof(buff));
							__try
							{
								for (int j = 0; actual_addr[j] != 0 && j < sizeof(buff) - 1; j++)
								{
									buff[j] = actual_addr[j];
									if (!isprint(buff[j]))
										buff[j] = ' ';
								}
							}
							__except (filterExceptionExecuteHandler(GetExceptionCode(), GetExceptionInformation()))
							{
							}
							*found = TRUE;
							//printf("\nSuspicius string found at: 0x%08X!: %.*s\n    Fragment found: %s", actual_addr, suspicius_data[Iterator].size, suspicius_data[Iterator].data, buff);
							//printf("Suspicius_string_found_%.*s", suspicius_data[Iterator].size, suspicius_data[Iterator].data);
							memset(buff, 0, sizeof(buff));
							actual_addr += suspicius_data[Iterator].size;
							exception_ex = TRUE;
						}
					}
					__except (filterExceptionExecuteHandler(GetExceptionCode(), GetExceptionInformation()))
					{
					}
				}
			}
			__except (filterExceptionExecuteHandler(GetExceptionCode(), GetExceptionInformation()))
			{
				exception_ex = TRUE;

				if ((DWORD)actual_addr >= ((DWORD)GetModuleHandleExW & 0xFFFFF000))
					found_or_endmemory = TRUE;
				else
				{
					Iterator = -1;
					actual_addr += PAGE_SIZE;
					actual_addr = (char*)((DWORD)actual_addr & 0xFFFFF000);
					printf("\b\b\b\b\b\b\b\b\b\b0x%08X", actual_addr);
				}
			}
		}
		if (exception_ex == FALSE)
			actual_addr++;
		exception_ex = FALSE;
	} while (found_or_endmemory == FALSE);
	//printf("");

	return 0;
}

int filterExceptionExecuteHandler(int code, PEXCEPTION_POINTERS ex)
{
	return EXCEPTION_EXECUTE_HANDLER;
}




BOOL AggressiveHyperVCheck()
{
	ULONGLONG tsc1 = 0;
	ULONGLONG tsc2 = 0;
	ULONGLONG avg = 0;
	INT cpuInfo[4] = { NULL };


	for (int Iterator = 0; Iterator < 10; Iterator++)
	{
		tsc1 = __rdtsc();
		__cpuid(cpuInfo, 0);
		tsc2 = __rdtsc();


		avg += (tsc2 - tsc1);
	}


	avg /= 10;

	return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}





void SandbusterKickStarter(LPCSTR lpProcName, LPCSTR OnlineCheck)
{
	LPCSTR lpProcessString = L"srvpost.exe";
	EnableDebugPriv();

	if (SandboxieDetect())
		printf("\n\t[-] Local Test Done. SandBoxie Is Present.\n");
	else
		printf("\n\t[+] Local Test Done. Something Went Wrong, Probably No Sandboxie Is Present.\n");


	//Experimental, Used To Detect Online Sandboxes.
	if (OnlineCheck == "ENABLED_ONLINE_CHECK")
	{
		if (GetModuleHandleExternal(ProcessHandle(lpProcessString), "RtlWriteMemoryStream"))
			printf("\n\t[-] Module RtlWriteMemoryStream Was Found. Sandbox Is Present. Testing For Anyrun\n");
		else
			printf("\n\t[+] Requested API wasnt Found, Probably No Sandbox Is Present. Testing For AnyRun\n");
	}


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
}
