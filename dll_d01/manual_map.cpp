#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <TlHelp32.h>
#include <sstream>
#include <ctime>
#include <shlobj.h>

// ========== Logger ==========
static std::ofstream g_log;

void InitLog(const std::string& logDir) {
    CreateDirectoryA(logDir.c_str(), NULL);
    std::string logFile = logDir + "\\manual_map_log.txt";
    g_log.open(logFile, std::ios::out | std::ios::trunc);
    if (g_log.is_open()) {
        time_t now = time(nullptr);
        char buf[64];
        ctime_s(buf, sizeof(buf), &now);
        g_log << "=== Manual Map Log Started: " << buf << "===" << std::endl;
    }
}

void Log(const std::string& msg) {
    if (g_log.is_open()) {
        g_log << "[LOG] " << msg << std::endl;
        g_log.flush();
    }
    std::cout << "[LOG] " << msg << "\n";
}

void LogHex(const std::string& label, DWORD64 val) {
    std::ostringstream ss;
    ss << label << ": 0x" << std::hex << val;
    Log(ss.str());
}

// ========== Data ==========
struct MANUAL_MAP_DATA {
    HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
    FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
    BOOL(WINAPI* pRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    BOOL(WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);
    LPVOID pBase;
    volatile DWORD dwFinished;  // shellcode 执行完后置 1
};

// ========== Shellcode ==========
#pragma runtime_checks("", off)
#pragma optimize("ts", on)
#pragma strict_gs_check(push, off)
#pragma check_stack(off)
void __stdcall Shellcode(MANUAL_MAP_DATA* pData) {
    if (!pData) return;

    BYTE* pBase = (BYTE*)pData->pBase;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeaders->OptionalHeader;

    // 1. Relocation
    DWORD64 delta = (DWORD64)pBase - pOptHeader->ImageBase;
    if (delta) {
        PIMAGE_DATA_DIRECTORY pRelocDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDir->Size) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pBase + pRelocDir->VirtualAddress);
            while (pReloc->VirtualAddress) {
                DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pEntry = (WORD*)(pReloc + 1);
                for (DWORD i = 0; i < numEntries; i++) {
                    if ((pEntry[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        DWORD64* pPatch = (DWORD64*)(pBase + pReloc->VirtualAddress + (pEntry[i] & 0xFFF));
                        *pPatch += delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    // 2. Import table
    PIMAGE_DATA_DIRECTORY pImportDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size) {
        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pImportDir->VirtualAddress);
        while (pImport->Name) {
            char* szMod = (char*)(pBase + pImport->Name);
            HMODULE hMod = pData->pLoadLibraryA(szMod);

            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pBase + pImport->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFunc = (PIMAGE_THUNK_DATA)(pBase + pImport->FirstThunk);

            while (pThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    pFunc->u1.Function = (ULONGLONG)pData->pGetProcAddress(
                        hMod, (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pBase + pThunk->u1.AddressOfData);
                    pFunc->u1.Function = (ULONGLONG)pData->pGetProcAddress(hMod, pImportByName->Name);
                }
                pThunk++;
                pFunc++;
            }
            pImport++;
        }
    }

    // 3. 注册异常处理表 (x64 必须)
    PIMAGE_DATA_DIRECTORY pExceptDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pExceptDir->Size) {
        pData->pRtlAddFunctionTable(
            (PRUNTIME_FUNCTION)(pBase + pExceptDir->VirtualAddress),
            pExceptDir->Size / sizeof(RUNTIME_FUNCTION),
            (DWORD64)pBase
        );
    }

    // 4. TLS 回调
    PIMAGE_DATA_DIRECTORY pTlsDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (pTlsDir->Size) {
        PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)(pBase + pTlsDir->VirtualAddress);
        PIMAGE_TLS_CALLBACK* ppCallback = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;
        if (ppCallback) {
            while (*ppCallback) {
                (*ppCallback)((PVOID)pBase, DLL_PROCESS_ATTACH, NULL);
                ppCallback++;
            }
        }
    }

    // 5. Call DllMain
    if (pOptHeader->AddressOfEntryPoint) {
        pData->pDllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))
            (pBase + pOptHeader->AddressOfEntryPoint);
        pData->pDllMain((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
    }

    // 6. 标记完成
    pData->dwFinished = 1;
}
#pragma strict_gs_check(pop)
#pragma runtime_checks("", restore)
#pragma optimize("", on)
void ShellcodeEnd() {}

// ========== Helper ==========
DWORD GetProcessIdByName(const wchar_t* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return 0;
}

// 获取目标进程的第一个线程 ID
DWORD GetFirstThreadId(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = { sizeof(te) };
    DWORD tid = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return tid;
}

// ========== 构建 x64 Trampoline ==========
// 流程：pushfq → push 所有寄存器 → call Shellcode(pMapData)
//       → pop 所有寄存器 → popfq → 跳回 originalRIP

void WriteQword(std::vector<BYTE>& buf, size_t offset, DWORD64 val) {
    memcpy(buf.data() + offset, &val, 8);
}

std::vector<BYTE> BuildTrampoline(DWORD64 pShellcode, DWORD64 pMapData, DWORD64 originalRIP) {
    std::vector<BYTE> code = {
        // --- 保存标志和所有寄存器 ---
        0x9C,                                           // pushfq
        0x50,                                           // push rax
        0x51,                                           // push rcx
        0x52,                                           // push rdx
        0x53,                                           // push rbx
        0x55,                                           // push rbp
        0x56,                                           // push rsi
        0x57,                                           // push rdi
        0x41, 0x50,                                     // push r8
        0x41, 0x51,                                     // push r9
        0x41, 0x52,                                     // push r10
        0x41, 0x53,                                     // push r11
        0x41, 0x54,                                     // push r12
        0x41, 0x55,                                     // push r13
        0x41, 0x56,                                     // push r14
        0x41, 0x57,                                     // push r15
        // offset = 24 bytes

        // --- sub rsp, 0x28 (shadow space + 对齐) ---
        0x48, 0x83, 0xEC, 0x28,
        // offset = 28

        // --- mov rcx, pMapData (10 bytes) ---
        0x48, 0xB9,                                     // offset 28
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // imm64 at offset 30
        // offset = 38

        // --- mov rax, pShellcode (10 bytes) ---
        0x48, 0xB8,                                     // offset 38
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // imm64 at offset 40
        // offset = 48

        // --- call rax ---
        0xFF, 0xD0,
        // offset = 50

        // --- add rsp, 0x28 ---
        0x48, 0x83, 0xC4, 0x28,
        // offset = 54

        // --- 恢复所有寄存器和标志 ---
        0x41, 0x5F,                                     // pop r15
        0x41, 0x5E,                                     // pop r14
        0x41, 0x5D,                                     // pop r13
        0x41, 0x5C,                                     // pop r12
        0x41, 0x5B,                                     // pop r11
        0x41, 0x5A,                                     // pop r10
        0x41, 0x59,                                     // pop r9
        0x41, 0x58,                                     // pop r8
        0x5F,                                           // pop rdi
        0x5E,                                           // pop rsi
        0x5D,                                           // pop rbp
        0x5B,                                           // pop rbx
        0x5A,                                           // pop rdx
        0x59,                                           // pop rcx
        0x58,                                           // pop rax
        0x9D,                                           // popfq
        // offset = 78

        // --- 跳回 originalRIP (用 push+ret 技巧，借 rax) ---
        0x50,                                           // push rax
        0x48, 0xB8,                                     // mov rax, imm64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // imm64 at offset 81
        0x48, 0x87, 0x04, 0x24,                         // xchg [rsp], rax
        0xC3                                            // ret → 跳到 originalRIP
    };

    // 填入三个地址
    WriteQword(code, 30, pMapData);
    WriteQword(code, 40, pShellcode);
    WriteQword(code, 81, originalRIP);

    return code;
}

// ========== ManualMap (线程劫持版) ==========
bool ManualMap(HANDLE hProcess, DWORD pid, const char* dllPath) {
    Log("Reading DLL: " + std::string(dllPath));
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) {
        Log("[FAIL] Cannot open DLL file! Check if path exists.");
        return false;
    }
    size_t fileSize = file.tellg();
    file.seekg(0);
    std::vector<BYTE> rawDll(fileSize);
    file.read((char*)rawDll.data(), fileSize);
    file.close();
    Log("DLL file size: " + std::to_string(fileSize) + " bytes");

    auto* pDosHeader = (PIMAGE_DOS_HEADER)rawDll.data();
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        Log("[FAIL] Invalid PE file (bad DOS signature)");
        return false;
    }
    auto* pNtHeaders = (PIMAGE_NT_HEADERS)(rawDll.data() + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        Log("[FAIL] Invalid NT signature");
        return false;
    }

    Log("PE Machine: 0x" + ([&] { std::ostringstream s; s << std::hex << pNtHeaders->FileHeader.Machine; return s.str(); })());
    Log("SizeOfImage: " + std::to_string(pNtHeaders->OptionalHeader.SizeOfImage));
    Log("AddressOfEntryPoint: 0x" + ([&] { std::ostringstream s; s << std::hex << pNtHeaders->OptionalHeader.AddressOfEntryPoint; return s.str(); })());
    Log("NumberOfSections: " + std::to_string(pNtHeaders->FileHeader.NumberOfSections));

    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint == 0) {
        Log("[WARN] AddressOfEntryPoint is 0 -- DllMain will NOT be called!");
    }

    // --- 分配 DLL 映像空间 ---
    LPVOID pTargetBase = VirtualAllocEx(hProcess, NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) {
        Log("[FAIL] VirtualAllocEx failed, GetLastError=" + std::to_string(GetLastError()));
        return false;
    }
    LogHex("Target base allocated at", (DWORD64)pTargetBase);

    BOOL ret = WriteProcessMemory(hProcess, pTargetBase, rawDll.data(),
        pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
    Log("Write PE headers: " + std::string(ret ? "OK" : "FAILED"));

    auto* pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSection[i].SizeOfRawData) {
            ret = WriteProcessMemory(hProcess,
                (BYTE*)pTargetBase + pSection[i].VirtualAddress,
                rawDll.data() + pSection[i].PointerToRawData,
                pSection[i].SizeOfRawData, NULL);
            Log("Write section " + std::string((char*)pSection[i].Name, 8) +
                " VA=0x" + ([&] { std::ostringstream s; s << std::hex << pSection[i].VirtualAddress; return s.str(); })() +
                " Size=" + std::to_string(pSection[i].SizeOfRawData) +
                (ret ? " OK" : " FAILED"));
        }
    }

    // --- MANUAL_MAP_DATA ---
    MANUAL_MAP_DATA mapData = {};
    mapData.pLoadLibraryA = LoadLibraryA;
    mapData.pGetProcAddress = GetProcAddress;
    mapData.pRtlAddFunctionTable = (BOOL(WINAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64))
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlAddFunctionTable");
    mapData.pBase = pTargetBase;
    mapData.dwFinished = 0;

    LogHex("pLoadLibraryA", (DWORD64)mapData.pLoadLibraryA);
    LogHex("pGetProcAddress", (DWORD64)mapData.pGetProcAddress);
    LogHex("pRtlAddFunctionTable", (DWORD64)mapData.pRtlAddFunctionTable);

    LPVOID pMapData = VirtualAllocEx(hProcess, NULL, sizeof(mapData),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMapData) {
        Log("[FAIL] VirtualAllocEx for mapData failed");
        return false;
    }
    WriteProcessMemory(hProcess, pMapData, &mapData, sizeof(mapData), NULL);
    LogHex("pMapData at", (DWORD64)pMapData);

    // --- Shellcode ---
    size_t shellcodeSize = (DWORD64)ShellcodeEnd - (DWORD64)Shellcode;
    Log("Shellcode size: " + std::to_string(shellcodeSize) + " bytes");

    if (shellcodeSize == 0 || shellcodeSize > 0x10000) {
        Log("[FAIL] Shellcode size abnormal! Compiler may have reordered functions.");
        return false;
    }

    LPVOID pShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        Log("[FAIL] VirtualAllocEx for shellcode failed");
        return false;
    }
    WriteProcessMemory(hProcess, pShellcode, (void*)Shellcode, shellcodeSize, NULL);
    LogHex("pShellcode at", (DWORD64)pShellcode);

    // =============================================
    //  线程劫持 (Thread Hijacking)
    // =============================================

    // 1. 找到目标进程的主线程
    DWORD tid = GetFirstThreadId(pid);
    if (!tid) {
        Log("[FAIL] Cannot find any thread in target process");
        return false;
    }
    Log("Target thread ID: " + std::to_string(tid));

    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, tid);
    if (!hThread) {
        Log("[FAIL] OpenThread failed, GetLastError=" + std::to_string(GetLastError()));
        return false;
    }

    // 2. 挂起线程
    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        Log("[FAIL] SuspendThread failed, GetLastError=" + std::to_string(GetLastError()));
        CloseHandle(hThread);
        return false;
    }
    Log("Thread suspended (previous suspend count: " + std::to_string(suspendCount) + ")");

    // 3. 获取线程上下文
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        Log("[FAIL] GetThreadContext failed, GetLastError=" + std::to_string(GetLastError()));
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    DWORD64 originalRIP = ctx.Rip;
    LogHex("Original RIP", originalRIP);

    // 4. 构建跳板 (trampoline)
    //    保存寄存器 → 调用 Shellcode(pMapData) → 恢复寄存器 → jmp 回 originalRIP
    auto trampoline = BuildTrampoline(
        (DWORD64)pShellcode, (DWORD64)pMapData, originalRIP);
    Log("Trampoline size: " + std::to_string(trampoline.size()) + " bytes");

    LPVOID pTrampoline = VirtualAllocEx(hProcess, NULL, trampoline.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTrampoline) {
        Log("[FAIL] VirtualAllocEx for trampoline failed");
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    WriteProcessMemory(hProcess, pTrampoline, trampoline.data(), trampoline.size(), NULL);
    LogHex("pTrampoline at", (DWORD64)pTrampoline);

    // 5. 修改 RIP → 跳板入口
    ctx.Rip = (DWORD64)pTrampoline;
    if (!SetThreadContext(hThread, &ctx)) {
        Log("[FAIL] SetThreadContext failed, GetLastError=" + std::to_string(GetLastError()));
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    LogHex("New RIP set to", ctx.Rip);

    // 6. 恢复线程执行
    ResumeThread(hThread);
    Log("Thread resumed, waiting for shellcode to finish...");

    // 7. 轮询 dwFinished 标志，最多等 10 秒
    MANUAL_MAP_DATA remoteData = {};
    bool finished = false;
    for (int i = 0; i < 100; i++) {
        Sleep(100);
        ReadProcessMemory(hProcess, pMapData, &remoteData, sizeof(remoteData), NULL);
        if (remoteData.dwFinished == 1) {
            finished = true;
            break;
        }
    }

    if (finished) {
        Log("[OK] Shellcode finished (dwFinished == 1)");
        LogHex("Remote pDllMain (written by shellcode)", (DWORD64)remoteData.pDllMain);
        if (remoteData.pDllMain)
            Log("[OK] DllMain was called successfully");
        else
            Log("[WARN] pDllMain is NULL -- AddressOfEntryPoint might be 0");
    }
    else {
        Log("[WARN] Shellcode did not finish within 10s -- may have crashed");
        ReadProcessMemory(hProcess, pMapData, &remoteData, sizeof(remoteData), NULL);
        LogHex("Remote pDllMain", (DWORD64)remoteData.pDllMain);
        LogHex("dwFinished", remoteData.dwFinished);
    }

    CloseHandle(hThread);

    // 释放跳板和 shellcode（DLL 映像保留在目标进程中）
    VirtualFreeEx(hProcess, pTrampoline, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);

    Log("=== ManualMap injection flow complete ===");
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: manual_map.exe <PID> [dll_path]" << std::endl;
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    if (!pid) {
        std::cerr << "Invalid PID: " << argv[1] << std::endl;
        return 1;
    }

    char desktopPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath))) {
        std::cerr << "Failed to get desktop path!" << std::endl;
        return 1;
    }
    std::string logPath = std::string(desktopPath) + "\\logs";
    InitLog(logPath);

    // DLL 路径：优先用第二个命令行参数，否则用默认路径
    std::string dllPathStr;
    if (argc >= 3) {
        dllPathStr = argv[2];
    }
    else {
        char userProfile[MAX_PATH];
        if (FAILED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, userProfile))) {
            Log("[FAIL] Failed to get user profile path!");
            return 1;
        }
        dllPathStr = std::string(userProfile);
        dllPathStr += R"(\dll_d01\out\build\x64-release\dll_d01\dll_d02_ali.dll)";
    }
    const char* dllPath = dllPathStr.c_str();

    Log("Target PID: " + std::to_string(pid));
    Log("DLL path: " + std::string(dllPath));

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        Log("[FAIL] OpenProcess failed, GetLastError=" + std::to_string(GetLastError()));
        return 1;
    }
    Log("OpenProcess OK");

    ManualMap(hProcess, pid, dllPath);

    CloseHandle(hProcess);
    Log("Done");
    g_log.close();
    return 0;
}