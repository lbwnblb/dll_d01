#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <TlHelp32.h>
#include <sstream>
#include <ctime>

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
    BOOL(WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);
    LPVOID pBase;
};

// ========== Shellcode ==========
void __stdcall Shellcode(MANUAL_MAP_DATA* pData) {
    if (!pData) return;

    BYTE* pBase = (BYTE*)pData->pBase;
    auto* pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    auto* pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    auto* pOptHeader = &pNtHeaders->OptionalHeader;

    // 1. Relocation
    DWORD64 delta = (DWORD64)pBase - pOptHeader->ImageBase;
    if (delta) {
        auto* pRelocDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDir->Size) {
            auto* pReloc = (PIMAGE_BASE_RELOCATION)(pBase + pRelocDir->VirtualAddress);
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
    auto* pImportDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size) {
        auto* pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pImportDir->VirtualAddress);
        while (pImport->Name) {
            char* szMod = (char*)(pBase + pImport->Name);
            HMODULE hMod = pData->pLoadLibraryA(szMod);

            auto* pThunk = (PIMAGE_THUNK_DATA)(pBase + pImport->OriginalFirstThunk);
            auto* pFunc = (PIMAGE_THUNK_DATA)(pBase + pImport->FirstThunk);

            while (pThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    pFunc->u1.Function = (ULONGLONG)pData->pGetProcAddress(
                        hMod, (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
                }
                else {
                    auto* pImportByName = (PIMAGE_IMPORT_BY_NAME)(pBase + pThunk->u1.AddressOfData);
                    pFunc->u1.Function = (ULONGLONG)pData->pGetProcAddress(hMod, pImportByName->Name);
                }
                pThunk++;
                pFunc++;
            }
            pImport++;
        }
    }

    // 3. Call DllMain
    if (pOptHeader->AddressOfEntryPoint) {
        pData->pDllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))
            (pBase + pOptHeader->AddressOfEntryPoint);
        pData->pDllMain((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
    }
}
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

// ========== ManualMap ==========
bool ManualMap(HANDLE hProcess, const char* dllPath) {
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

    MANUAL_MAP_DATA mapData = {};
    mapData.pLoadLibraryA = LoadLibraryA;
    mapData.pGetProcAddress = GetProcAddress;
    mapData.pBase = pTargetBase;

    LogHex("pLoadLibraryA", (DWORD64)mapData.pLoadLibraryA);
    LogHex("pGetProcAddress", (DWORD64)mapData.pGetProcAddress);

    LPVOID pMapData = VirtualAllocEx(hProcess, NULL, sizeof(mapData),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMapData) {
        Log("[FAIL] VirtualAllocEx for mapData failed");
        return false;
    }
    WriteProcessMemory(hProcess, pMapData, &mapData, sizeof(mapData), NULL);
    LogHex("pMapData at", (DWORD64)pMapData);

    size_t shellcodeSize = (DWORD64)ShellcodeEnd - (DWORD64)Shellcode;
    Log("Shellcode size: " + std::to_string(shellcodeSize) + " bytes");

    if (shellcodeSize == 0 || shellcodeSize > 0x10000) {
        Log("[FAIL] Shellcode size abnormal! Compiler may have reordered functions.");
        Log("  Shellcode addr: 0x" + ([&] { std::ostringstream s; s << std::hex << (DWORD64)Shellcode; return s.str(); })());
        Log("  ShellcodeEnd addr: 0x" + ([&] { std::ostringstream s; s << std::hex << (DWORD64)ShellcodeEnd; return s.str(); })());
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

    Log("Creating remote thread...");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pShellcode, pMapData, 0, NULL);
    if (!hThread) {
        Log("[FAIL] CreateRemoteThread failed, GetLastError=" + std::to_string(GetLastError()));
        return false;
    }
    Log("Remote thread created, waiting...");

    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    if (waitResult == WAIT_TIMEOUT) {
        Log("[WARN] Remote thread timed out (10s)!");
    }
    else if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        Log("Remote thread finished, exitCode=" + std::to_string(exitCode));
    }
    else {
        Log("[WARN] WaitForSingleObject unexpected: " + std::to_string(waitResult));
    }
    CloseHandle(hThread);

    // Read back to check if shellcode set pDllMain
    MANUAL_MAP_DATA remoteData = {};
    ReadProcessMemory(hProcess, pMapData, &remoteData, sizeof(remoteData), NULL);
    LogHex("Remote pDllMain (written by shellcode)", (DWORD64)remoteData.pDllMain);
    if (remoteData.pDllMain == nullptr) {
        Log("[WARN] pDllMain is NULL -- shellcode likely crashed or did not run!");
    }
    else {
        Log("[OK] pDllMain was set -- DllMain should have been called");
    }

    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);

    Log("=== ManualMap injection flow complete ===");
    return true;
}

int main() {
    std::string logPath = R"(C:\Users\27817\Desktop\logs)";
    InitLog(logPath);

    const wchar_t* targetProcess = L"AliWorkbench.exe";
    const char* dllPath = R"(D:\Users\27817\source\repos\dll_d01\out\build\x64-release\dll_d01\dll_d02_ali.dll)";

    Log("Target process: AliWorkbench.exe");
    Log("DLL path: " + std::string(dllPath));

    DWORD pid = GetProcessIdByName(targetProcess);
    if (!pid) {
        Log("[FAIL] Target process not found!");
        return 1;
    }
    Log("Target PID: " + std::to_string(pid));

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        Log("[FAIL] OpenProcess failed, GetLastError=" + std::to_string(GetLastError()));
        return 1;
    }
    Log("OpenProcess OK");

    ManualMap(hProcess, dllPath);

    CloseHandle(hProcess);
    Log("Done");
    g_log.close();
    return 0;
}