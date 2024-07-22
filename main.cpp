#pragma comment(lib, "detours.lib")
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <wchar.h>
#include <detours.h>
#include "mssign32.h"

HMODULE hModCrypt32 = NULL, hModMssign32 = NULL, hModKernel32 = NULL;
using fntCertVerifyTimeValidity = decltype(CertVerifyTimeValidity);
using fntSignerSign = decltype(SignerSign);
using fntSignerTimeStamp = decltype(SignerTimeStamp);
using fntSignerTimeStampEx2 = decltype(SignerTimeStampEx2);
using fntSignerTimeStampEx3 = decltype(SignerTimeStampEx3);
using fntGetLocalTime = decltype(GetLocalTime);
fntCertVerifyTimeValidity* pOldCertVerifyTimeValidity = NULL;
fntSignerSign* pOldSignerSign = NULL;
fntSignerTimeStamp* pOldSignerTimeStamp = NULL;
fntSignerTimeStampEx2* pOldSignerTimeStampEx2 = NULL;
fntSignerTimeStampEx3* pOldSignerTimeStampEx3 = NULL;
fntGetLocalTime* pOldGetLocalTime = NULL;

int year = -1, month = -1, day = -1, hour = -1, minute = -1, second = -1;
WCHAR lpTimestamp_SHA1[2560];
WCHAR lpTimestamp_SHA256[2560];

LPCWSTR ReplaceTimeStamp(LPCWSTR lpOriginalTS) {
    if (!lpOriginalTS)
        return NULL;
    if (!_wcsicmp(lpOriginalTS, L"{CustomTimestampMarker-SHA1}")) {
        return lpTimestamp_SHA1;
    }
    else if (!_wcsicmp(lpOriginalTS, L"{CustomTimestampMarker-SHA256}")) {
        return lpTimestamp_SHA256;
    }
    else {
        return lpOriginalTS;
    }
}

LONG WINAPI NewCertVerifyTimeValidity(
    LPFILETIME pTimeToVerify,
    PCERT_INFO pCertInfo
)
{
    return 0;
}

HRESULT WINAPI NewSignerSign(
    SIGNER_SUBJECT_INFO* pSubjectInfo,
    SIGNER_CERT* pSignerCert,
    SIGNER_SIGNATURE_INFO* pSignatureInfo,
    SIGNER_PROVIDER_INFO* pProviderInfo,
    LPCWSTR pwszHttpTimeStamp,
    PCRYPT_ATTRIBUTES psRequest,
    LPVOID pSipData
)
{
    return (*pOldSignerSign)(pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo, ReplaceTimeStamp(pwszHttpTimeStamp), psRequest, pSipData);
}

HRESULT WINAPI NewSignerTimeStamp(
    SIGNER_SUBJECT_INFO* pSubjectInfo,
    LPCWSTR pwszHttpTimeStamp,
    PCRYPT_ATTRIBUTES psRequest,
    LPVOID pSipData
)
{
    return (*pOldSignerTimeStamp)(pSubjectInfo, ReplaceTimeStamp(pwszHttpTimeStamp), psRequest, pSipData);
}

HRESULT WINAPI NewSignerTimeStampEx2(
    DWORD dwFlags,
    SIGNER_SUBJECT_INFO* pSubjectInfo,
    LPCWSTR pwszHttpTimeStamp,
    ALG_ID dwAlgId,
    PCRYPT_ATTRIBUTES psRequest,
    LPVOID pSipData,
    SIGNER_CONTEXT** ppSignerContext
)
{
    return (*pOldSignerTimeStampEx2)(dwFlags, pSubjectInfo, ReplaceTimeStamp(pwszHttpTimeStamp), dwAlgId, psRequest, pSipData, ppSignerContext);
}

HRESULT WINAPI NewSignerTimeStampEx3(
    DWORD dwFlags,
    DWORD dwIndex,
    SIGNER_SUBJECT_INFO* pSubjectInfo,
    PCWSTR pwszHttpTimeStamp,
    PCWSTR pszAlgorithmOid,
    PCRYPT_ATTRIBUTES psRequest,
    PVOID pSipData,
    SIGNER_CONTEXT** ppSignerContext,
    PCERT_STRONG_SIGN_PARA pCryptoPolicy,
    PVOID pReserved
)
{
    return (*pOldSignerTimeStampEx3)(dwFlags, dwIndex, pSubjectInfo, ReplaceTimeStamp(pwszHttpTimeStamp), pszAlgorithmOid, psRequest, pSipData, ppSignerContext, pCryptoPolicy, pReserved);
}

void WINAPI NewGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
    (*pOldGetLocalTime)(lpSystemTime);
    if (year >= 0) lpSystemTime->wYear = year;
    if (month >= 0) lpSystemTime->wMonth = month;
    if (day >= 0) lpSystemTime->wDay = day;
    if (hour >= 0) lpSystemTime->wHour = hour;
    if (minute >= 0) lpSystemTime->wMinute = minute;
    if (second >= 0) lpSystemTime->wSecond = second;
}

bool HookFunctions()
{
    hModCrypt32 = LoadLibraryW(L"crypt32.dll");
    hModMssign32 = LoadLibraryW(L"mssign32.dll");
    hModKernel32 = LoadLibraryW(L"kernel32.dll");
    if (!hModCrypt32 || !hModMssign32 || !hModKernel32)
        return false;

    pOldCertVerifyTimeValidity = (fntCertVerifyTimeValidity*)GetProcAddress(hModCrypt32, "CertVerifyTimeValidity");
    pOldSignerSign = (fntSignerSign*)GetProcAddress(hModMssign32, "SignerSign");
    pOldSignerTimeStamp = (fntSignerTimeStamp*)GetProcAddress(hModMssign32, "SignerTimeStamp");
    pOldSignerTimeStampEx2 = (fntSignerTimeStampEx2*)GetProcAddress(hModMssign32, "SignerTimeStampEx2");
    pOldSignerTimeStampEx3 = (fntSignerTimeStampEx3*)GetProcAddress(hModMssign32, "SignerTimeStampEx3");
    pOldGetLocalTime = (fntGetLocalTime*)GetProcAddress(hModKernel32, "GetLocalTime");
    if (!pOldCertVerifyTimeValidity || !pOldSignerSign || !pOldSignerTimeStamp || !pOldSignerTimeStampEx2 || !pOldGetLocalTime || (pOldSignerTimeStampEx3 == NULL && GetLastError() != ERROR_PROC_NOT_FOUND))
        return false;

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)pOldCertVerifyTimeValidity, NewCertVerifyTimeValidity);
    DetourAttach(&(PVOID&)pOldSignerSign, NewSignerSign);
    DetourAttach(&(PVOID&)pOldSignerTimeStamp, NewSignerTimeStamp);
    DetourAttach(&(PVOID&)pOldSignerTimeStampEx2, NewSignerTimeStampEx2);
    if (pOldSignerTimeStampEx3)
        DetourAttach(&(PVOID&)pOldSignerTimeStampEx3, NewSignerTimeStampEx3);
    DetourAttach(&(PVOID&)pOldGetLocalTime, NewGetLocalTime);
    DetourTransactionCommit();

    return true;
}

bool ParseConfig(LPWSTR lpCommandLineConfig, LPWSTR lpCommandLineTimestamp_SHA1, LPWSTR lpCommandLineTimestamp_SHA256)
{
    WCHAR buf[5120] = { 0 };
    _wgetcwd(buf, 5120);
    wcscat(buf, L"\\");

    if (lpCommandLineConfig) {
        if ((wcschr(lpCommandLineConfig, L':') - lpCommandLineConfig) == 1) {
            wcscpy(buf, lpCommandLineConfig);
        }
        else {
            wcscat(buf, lpCommandLineConfig);
        }
    }
    else {
        wcscat(buf, L"hook.ini");
    }

    year = GetPrivateProfileIntW(L"Time", L"Year", -1, buf);
    month = GetPrivateProfileIntW(L"Time", L"Month", -1, buf);
    day = GetPrivateProfileIntW(L"Time", L"Day", -1, buf);
    hour = GetPrivateProfileIntW(L"Time", L"Hour", -1, buf);
    minute = GetPrivateProfileIntW(L"Time", L"Minute", -1, buf);
    second = GetPrivateProfileIntW(L"Time", L"Second", -1, buf);

    if (lpCommandLineTimestamp_SHA1)
        wcscpy(lpTimestamp_SHA1, lpCommandLineTimestamp_SHA1);
    if (lpCommandLineTimestamp_SHA256)
        wcscpy(lpTimestamp_SHA256, lpCommandLineTimestamp_SHA256);
    if (!lpCommandLineTimestamp_SHA1 && !lpCommandLineTimestamp_SHA256) {
        GetPrivateProfileStringW(L"Timestamp", L"Timestamp_SHA1", NULL, lpTimestamp_SHA1, 2560, buf);
        GetPrivateProfileStringW(L"Timestamp", L"Timestamp_SHA256", NULL, lpTimestamp_SHA256, 2560, buf);
    }

    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        LPWSTR* szArglist = NULL;
        int nArgs = 0;
        szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);

        int iconfig = -1, isha1 = -1, isha256 = -1;

        for (int i = 0; i <= nArgs - 2; i++) {
            if (wcscmp(szArglist[i], L"-config") == 0)
                iconfig = i + 1;
            if (wcscmp(szArglist[i], L"--timestamp-sha1") == 0)
                isha1 = i + 1;
            if (wcscmp(szArglist[i], L"--timestamp-sha256") == 0)
                isha256 = i + 1;
        }

        if (!ParseConfig(iconfig >= 0 ? szArglist[iconfig] : NULL, isha1 >= 0 ? szArglist[isha1] : NULL, isha256 >= 0 ? szArglist[isha256] : NULL))
            MessageBoxW(NULL, L"配置初始化失败，请检查hook.ini和命令行参数！", L"初始化失败", MB_ICONERROR);

        LocalFree(szArglist);

        if (!HookFunctions())
            MessageBoxW(NULL, L"出现错误，无法Hook指定的函数\r\n请关闭程序重试！", L"Hook失败", MB_ICONERROR);

        LPWSTR lpTimestamp = new WCHAR[5120];
        memset(lpTimestamp, 0, sizeof(WCHAR) * 5120);
        WCHAR SHA256[16];
        memset(SHA256, 0, sizeof(WCHAR) * 16);
        if (wcslen(lpTimestamp_SHA1) != 0) {
            wcscat(lpTimestamp, L"SHA1：");
            wcscat(lpTimestamp, lpTimestamp_SHA1);
        }
        if (wcslen(lpTimestamp_SHA1) != 0 && wcslen(lpTimestamp_SHA256) != 0) {
            wcscat(SHA256, L"\nSHA256：");
        }
        else {
            wcscat(SHA256, L"SHA256：");
        }
        if (wcslen(lpTimestamp_SHA256) != 0) {
            wcscat(lpTimestamp, SHA256);
            wcscat(lpTimestamp, lpTimestamp_SHA256);
        }
        if (wcslen(lpTimestamp_SHA1) != 0 || wcslen(lpTimestamp_SHA256) != 0) {
            MessageBoxW(NULL, lpTimestamp, L"自定义时间戳URL为：", MB_OK);
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int attach()
{
    return 0;
}
