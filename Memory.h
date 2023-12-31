#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <iostream>
using namespace std;

class Memory
{
public:
	struct Module
	{
		uintptr_t lpBaseOfDll;
		uintptr_t SizeOfImage;
	};
private:
	HANDLE _Process;
	uintptr_t _ProcessID;
public:
	Memory() { _Process = GetCurrentProcess(); _ProcessID = GetCurrentProcessId(); }
	uintptr_t trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size);
	uintptr_t trampolineHook(uintptr_t _Dst, uintptr_t _Src, size_t _Size, size_t _SkipBytes);
	uintptr_t VTableFunctionSwap(uintptr_t _Dst, uintptr_t _Src, size_t _Offset);
	uintptr_t VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size);
	uintptr_t VTableFunctionTrampoline(uintptr_t _Dst, uintptr_t _Src, size_t _Offset, size_t _Size, size_t _SkipBytes);
	Memory::Module LoadModule(char* _Module);
	bool CompareData(const BYTE* _PDATA, const BYTE* _PMASK, const char* _PSZMASK);
	uintptr_t FindPattern(char* _Module, const char* _Signature, const char* _Mask);
	uintptr_t FindPattern(const char* _Signature, const char* _Mask, uintptr_t _Protect);
	uintptr_t FindArray(char* _Module, const char* _Mask , int argCount, ...);
	int GetThreadList(uintptr_t _ThreadArray[]);
	HANDLE GetProcess();
	uintptr_t GetProcessID();

	template <class Mem>
	Mem Read(uintptr_t dwAddress)
	{
		Mem value;
		ReadProcessMemory(_Process, (LPVOID)dwAddress, &value, sizeof(Mem), NULL);
		return value;
	}

	template <class Mem>
	void Write(uintptr_t dwAddress, Mem value)
	{
		WriteProcessMemory(_Process, (LPVOID)dwAddress, &value, sizeof(Mem), NULL);
	}

};
