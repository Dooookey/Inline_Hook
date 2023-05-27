// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>

PROC m_FuncAddress;
BYTE m_OldBytes[12];
BYTE m_NewBytes[12];

BOOL Hook(const char* pszModuleName, const char* pszFuncName, PROC pfnHookFunc)
{
    m_FuncAddress = GetProcAddress(GetModuleHandle(pszModuleName), pszFuncName);
    if (m_FuncAddress == 0)
    {
        return FALSE;
    }
    SIZE_T dwSize = 0;
    ReadProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 12, &dwSize);
    m_NewBytes[0] = '\x48';
    m_NewBytes[1] = '\xb8';
    m_NewBytes[10] = '\xff';
    m_NewBytes[11] = '\xe0';
    *(DWORD64*)(m_NewBytes + 2) = (DWORD64)pfnHookFunc;
    WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 12, &dwSize);
    return TRUE;
}

BOOL UnHook()
{
    if (m_FuncAddress == 0)
    {
        return FALSE;
    }
    SIZE_T dwSize = 0;
    WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 12, &dwSize);
    return TRUE;
}

BOOL ReHook()
{
    if (m_FuncAddress == 0)
    {
        return FALSE;
    }
    SIZE_T dwSize = 0;
    WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 12, &dwSize);
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
    int nRet = MessageBoxA(hWnd, "Dokey 12", "Dokey 12", uType);
    ReHook();
    return nRet;
}

int
WINAPI
MyMessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    UnHook();
    int nRet = MessageBoxW(hWnd, L"Dokey 12", L"Dokey 12", uType);
    ReHook();
    return nRet;
}

#ifdef UNICODE
#define MyMessageBox  MyMessageBoxW
constexpr auto MessageBoxText = "MessageBoxW";
#else
#define MyMessageBox  MyMessageBoxA
constexpr auto MessageBoxText = "MessageBoxA";
#endif // !UNICODE

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        m_FuncAddress = NULL;
        memset(m_OldBytes, 0, 12);
        memset(m_NewBytes, 0, 12);
        Hook("user32.dll", MessageBoxText, (PROC)MyMessageBox);
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
