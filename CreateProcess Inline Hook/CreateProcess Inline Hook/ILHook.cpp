#include "pch.h"
#include "ILHook.h"

CILHook::CILHook()
{
	// �Գ�Ա�����ĳ�ʼ��
	m_FuncAddress = NULL;
#ifdef _WIN64
	memset(m_OldBytes, 0, 12);
	memset(m_NewBytes, 0, 12);
#else
	memset(m_OldBytes, 0, 7);
	memset(m_NewBytes, 0, 7);
#endif // _WIN64

}

CILHook::~CILHook()
{
	// ȡ��Hook
	UnHook();
	m_FuncAddress = NULL;
#ifdef _WIN64
	memset(m_OldBytes, 0, 12);
	memset(m_NewBytes, 0, 12);
#else
	memset(m_OldBytes, 0, 7);
	memset(m_NewBytes, 0, 7);
#endif // _WIN64
}

BOOL CILHook::Hook(LPCWSTR pszModuleName, const char* pszFuncName, PROC pfnHookFunc)
{
	/*
	�������ƣ�Hook
	�������ܣ���ָ��ģ���еĺ������йҹ�
	����˵����
		pszModuleName��ģ������
		pszFuncName����������
		pfnHookFunc�����Ӻ���
	*/
	m_FuncAddress = GetProcAddress(GetModuleHandle(pszModuleName), pszFuncName);
	if (m_FuncAddress == NULL)
	{
		return 1;
	}
	SIZE_T dwSize = 0;
#ifdef _WIN64
	ReadProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 12, &dwSize);
	m_NewBytes[0] = '\x48';
	m_NewBytes[1] = '\xb8';
	m_NewBytes[10] = '\xff';
	m_NewBytes[11] = '\xe0';
	*(DWORD64*)(m_NewBytes + 2) = (DWORD64)pfnHookFunc;
	WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 12, &dwSize);
#else
	ReadProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 7, &dwSize);
	m_NewBytes[0] = '\xb8';
	m_NewBytes[5] = '\xff';
	m_NewBytes[6] = '\xe0';
	*(DWORD*)(m_NewBytes + 1) = (DWORD)pfnHookFunc;
	WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 7, &dwSize);
#endif // _WIN64

	return 0;
}

BOOL CILHook::UnHook()
{
	if (m_FuncAddress == 0)
	{
		return 1;
	}
	SIZE_T dwSize = 0;
#ifdef _WIN64
	WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 12, &dwSize);
#else
	WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_OldBytes, 7, &dwSize);
#endif // _WIN64

	return 0;
}

BOOL CILHook::ReHook()
{
	if (m_FuncAddress == 0)
	{
		return 1;
	}
	SIZE_T dwSize = 0;
#ifdef _WIN64
	WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 12, &dwSize);
#else
	WriteProcessMemory(GetCurrentProcess(), m_FuncAddress, m_NewBytes, 7, &dwSize);
#endif // _WIN64
	return 0;
}
