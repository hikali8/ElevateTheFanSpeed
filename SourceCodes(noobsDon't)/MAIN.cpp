#include <iostream>
#include <windows.h>

#include "ec.hpp"

BOOL IsRunAsAdministrator()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:

    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsRunAsAdmin;
}

void ElevateUAC()
{
    BOOL bAlreadyRunningAsAdministrator = FALSE;
    try
    {
        bAlreadyRunningAsAdministrator = IsRunAsAdministrator();
    }
	catch(...){}
    if (!bAlreadyRunningAsAdministrator)
    {
        TCHAR szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
        {
            SHELLEXECUTEINFO sei = { sizeof(sei) };

            sei.lpVerb = "runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_SHOWDEFAULT;

            if (!ShellExecuteEx(&sei))
            {
                DWORD dwError = GetLastError();
                if (dwError == ERROR_CANCELLED)
                    //Annoys you to Elevate it LOL
                    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ElevateUAC, 0, 0, 0);
            }
        }

    }
}



int main()
{
	ElevateUAC();
	
	EmbeddedController ec = EmbeddedController();
	for(int i = 3; i--;){
		if(ec.readByte(189) == 0x80)
			return 0;
		if (ec.driverFileExist && ec.driverLoaded)
			ec.writeByte(189, 0x80);
		Sleep(1);
	}
	std::cout << "Failed!" << std::endl;
	return 1;
}
