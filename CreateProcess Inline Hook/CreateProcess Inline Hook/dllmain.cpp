// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include"ILHook.h"

CILHook CreateProcessHook;

BOOL
WINAPI
MyCreateProcessA(
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
) 
{
    BOOL bRet = FALSE;
    if (MessageBoxA(NULL, lpApplicationName, lpCommandLine, MB_YESNO) == IDYES)
    {
        CreateProcessHook.UnHook();
        bRet = CreateProcessA(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation
        );
        CreateProcessHook.ReHook();
    }
    else
    {
        MessageBoxA(NULL, "启动的程序被拦截", "提示", MB_OK);
    }
    return bRet;
}

BOOL
WINAPI
MyCreateProcessW(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
)
{
    BOOL bRet = FALSE;
    if (MessageBoxW(NULL, lpApplicationName, lpCommandLine, MB_YESNO) == IDYES)
    {
        CreateProcessHook.UnHook();
        bRet = CreateProcessW(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation
        );
        CreateProcessHook.ReHook();
    }
    else
    {
        MessageBoxW(NULL, L"启动的程序被拦截", L"提示", MB_OK);
    }
    return bRet;
}

#ifdef UNICODE
#define MyCreateProcess  MyCreateProcessW
constexpr auto CreateProcessText = "CreateProcessW";
#else
#define MyCreateProcess  MyCreateProcessA
constexpr auto CreateProcessText = "CreateProcessA";
#endif // !UNICODE

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateProcessHook.Hook(L"kernel32.dll", CreateProcessText, (PROC)MyCreateProcess);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        CreateProcessHook.UnHook();
        break;
    }
    return TRUE;
}

