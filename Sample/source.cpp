#include ".../include/sandbuster.h"

int wmain(int argc, wchar_t* argv[])
{
	LPCSTR lpwProcName = L"sandbuster.exe"; //be sure to give the correct process name
	//avoid it for now
	//SandbusterKickStarter(lpwProcName,"ENABLED_ONLINE_CHECK");
	SandbusterKickStarter(lpwProcName, NULL);

	getchar();

	return -1;
}
