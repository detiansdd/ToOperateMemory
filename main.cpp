#include <iostream>
#include <Windows.h>
#include <string>
#include <stack>
#include "Memory.h"

Memory memory;


bool IsDebugerPresentBypass()
{
	uint8_t patch[] = { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x40, 0x02, 0x33, 0xC0, 0xC3 };
	uintptr_t address = memory.FindPattern((char*)"KERNELBASE.dll", "\x00\x00\x00\x00\x00\x00\x0F\xB6\x40\x02\xC3\xCC\xCC\xCC\xCC\xCC\x8B\xFF", "??????xxxxxxxxxxxx");
	if (!WriteProcessMemory(memory.GetProcess(), (LPVOID)address, (LPCVOID)&patch, sizeof(patch), NULL))
	{
		return false;
	}
	else
	{
		cout << "[*] Patched all " << dec << sizeof(patch) << " bytes at: 0x" << hex << address << endl;
		return true;
	}
}

bool changePEBBeingDebuggedFlag()
{
	uintptr_t address = NULL;
	__asm
	{
		mov eax, dword ptr fs : [0x00000030]
		add eax, 0x2
		mov address, eax
	}


	cout << "[+] PEB->BeingDebugged address at: 0x" << hex << address << endl;
	memory.Write<BYTE>(address, 0x0); //auto peb = (char*)__readfsdword(0x30); *(peb + 0x02) = 0x00;
	if ((uintptr_t)memory.Read<BYTE>(address) == 0x0)
	{
		cout << "[*] Successfully bypassed PEB->BeingDebugged" << endl;
		return true;
	}
	
	return false;
}

bool changePEBNtGlobalFlag()
{
	uintptr_t address = NULL;

	__asm
	{
		mov eax, dword ptr fs : [0x00000030]
		add eax, 0x68
		mov address, eax

	}

	cout << "[+] PEB->NtGlobalFlag address at: 0x" << hex << address << endl;
	cout << "[+] PEB->NtGlobalFlag value is: 0x" << hex << (uintptr_t)memory.Read<BYTE>(address) << endl;
	cout << "[+] Changing PEB->NtGlobalFlag value to 0x0" << endl;
	memory.Write<BYTE>(address, 0x0);//auto peb = (char*)__readfsdword(0x30); *(peb + 0x68) = 0x00;
	if ((uintptr_t)memory.Read<BYTE>(address) == 0x0)
	{
		cout << "[+] PEB->NtGlobalFlag value is: 0x" << hex << (uintptr_t)memory.Read<BYTE>(address) << endl;
		cout << "[*] Successfully bypassed PEB->NtGlobalFlag" << endl;
		return true;
	}
	return false;
}

bool CheckRemoteDebuggerPresentBypass()
{
	uint8_t patch[] = { 0x90, 0x90 };
	uintptr_t address = memory.FindPattern((char*)"KERNELBASE.dll", "\x00\x09\x8B\xC8\xE8\x00\x00\x00\x00\xEB\x17\x33\xC0\x39\x45\xFC\x0F\x95\xC0\x89\x06\x33\xC0\x40\xEB\x0A\x6A\x57\xFF\x15\x00\x00\x00\x00\x33\xC0\x5E\xC9\xC2\x08\x00", "?xxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx");
	if (!WriteProcessMemory(memory.GetProcess(), (LPVOID)address, (LPCVOID)patch, sizeof(patch), NULL))
	{
		return false;
	}
	else
	{
		cout << "[*] Patched all " << dec << sizeof(patch) << " bytes at: 0x" << hex << address << endl;
		return true;
	}
}

bool CheckParentProcessBypass()
{
	uint8_t patch[] = { 0x90, 0x90 };
	uintptr_t address = memory.FindPattern((char*)"anti-debugging.exe", "\x00\x00\x8B\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x83\xC7\x18\x40\x89\x00\x00\x00\x00\x00\x83\xF8\x16\x0F\x82", "??x?????x?????xxxxx?????xxxxx");
	if (!WriteProcessMemory(memory.GetProcess(), (LPVOID)address, (LPCVOID)patch, sizeof(patch), NULL))
	{
		return false;
	}
	else
	{
		cout << "[*] Patched all " << dec << sizeof(patch) << " bytes at: 0x" << hex << address << endl;
		return true;
	}
}

bool UnhandledExceptionFilterCheckBypass()
{
	uint8_t patch[] = { 0x90, 0xB0, 0x00, 0xC3 };
	uintptr_t address = (memory.FindPattern((char*)"anti-debugging.exe", "\xC6\x05\x00\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x00\xA0\x00\x00\x00\x00\xC3\xCC", "xx?????xx?????x????xx") + 0xD);
	if (!WriteProcessMemory(memory.GetProcess(), (LPVOID)address, (LPCVOID)patch, sizeof(patch), NULL))
	{
		return false;
	}
	else
	{
		cout << "[*] Patched all " << dec << sizeof(patch) << " bytes at: 0x" << hex << address << endl;
		return true;
	}
}

DWORD WINAPI MainThread(LPVOID param) // our main thread
{
	cout << "[+] Bypassing IsDebuggerPresent()" << endl;
	if (!IsDebugerPresentBypass())
	{
		cout << "[x] Error" << endl;
	}

	cout << "[+] Bypassing PEB->BeingDebugged" << endl;
	if (!changePEBBeingDebuggedFlag())
	{
		cout << "[x] Error" << endl;
	}

	cout << "[+] Bypassing PEB->NtGlobalFlag" << endl; 
	if (!changePEBNtGlobalFlag())
	{
		cout << "[x] Error" << endl;
	}

	cout << "[+] Bypassing CheckRemoteDebuggerPresent()" << endl;
	if (!CheckRemoteDebuggerPresentBypass())
	{
		cout << "[x] Error" << endl;
	}

	cout << "[+] Bypassing Check Parent Process" << endl;
	if (!CheckParentProcessBypass())
	{
		cout << "[x] Error" << endl;
	}

	cout << "[+] Bypassing UnhandledExceptionFilterCheck" << endl;
	if (!UnhandledExceptionFilterCheckBypass())
	{
		cout << "[x] Error" << endl;
	}

	return false;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		AllocConsole(); // enables the console
		freopen("CONIN$", "r", stdin); // makes it possible to output to console with cout.
		freopen("CONOUT$", "w", stdout);
		CreateThread(0, 0, MainThread, hModule, 0, 0); // creates our thread 
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;

}

