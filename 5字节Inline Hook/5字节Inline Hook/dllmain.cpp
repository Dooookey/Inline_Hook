// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>

PROC m_FuncAddress;
BYTE m_OldBytes[5];
BYTE m_NewBytes[5];

BOOL Hook(const char* pszModuleName, const char* pszFuncName, PROC pfnHookFunc)
{
    m_FuncAddress = GetProcAddress(GetModuleHandle(pszModuleName), pszFuncName);
    if (m_FuncAddress == NULL)
    {
        return FALSE;
    }
    SIZE_T dwSize = 0;
    ReadProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 5, &dwSize);
    m_NewBytes[0] = '\xE9';
    *(DWORD*)(m_NewBytes + 1) = (DWORD)pfnHookFunc - (DWORD)m_FuncAddress - 5;
    WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 5, &dwSize);
    return TRUE;
}

BOOL UnHook()
{
    if (m_FuncAddress == 0)
    {
        return FALSE;
    }
    SIZE_T dwSize = 0;
    WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 5, &dwSize);
    return TRUE;
}

BOOL ReHook()
{
    if (m_FuncAddress == 0)
    {
        return FALSE;
    }
    SIZE_T dwSize = 0;
    WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 5, &dwSize);
    return TRUE;
}

int
WINAPI
MyMessageBoxA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType) 
{
    UnHook();
    int nRet = MessageBox(hWnd, "Dokey", "Dokey", uType);
    ReHook();
    return nRet;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        m_FuncAddress = NULL;
        memset(m_OldBytes, 0, 5);
        memset(m_NewBytes, 0, 5);
        Hook("user32.dll", "MessageBoxA", (PROC)MyMessageBoxA);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        UnHook();
        break;
    }
    return TRUE;
}

