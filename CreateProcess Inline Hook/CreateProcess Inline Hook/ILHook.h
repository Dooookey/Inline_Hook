#pragma once
#include <Windows.h>

class CILHook
{
public:
	CILHook();
	~CILHook();

	// Hook����
	BOOL Hook(
		LPCWSTR pszModuleName,		// Hookģ������
		const char* pszFuncName,		// Hook��API��������
		PROC pfnHookFunc				// Ҫ�滻�ĺ�����ַ
	);

	// ȡ��Hook����
	BOOL UnHook();

	// ����Hook����
	BOOL ReHook();

private:
	PROC m_FuncAddress;
#ifdef _WIN64
	BYTE m_OldBytes[12];
	BYTE m_NewBytes[12];
#else
	BYTE m_OldBytes[7];
	BYTE m_NewBytes[7];
#endif // !_WIN64

};