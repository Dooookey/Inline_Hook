#pragma once
#include <Windows.h>

class CILHook
{
public:
	CILHook();
	~CILHook();

	// Hook函数
	BOOL Hook(
		LPCWSTR pszModuleName,		// Hook模块名称
		const char* pszFuncName,		// Hook的API函数名称
		PROC pfnHookFunc				// 要替换的函数地址
	);

	// 取消Hook函数
	BOOL UnHook();

	// 重新Hook函数
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