#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <TlHelp32.h>

// ========== 数据结构 ==========
struct MANUAL_MAP_DATA {
    HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
    FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
    BOOL(WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);
    LPVOID pBase;
};

// ========== Shellcode：在目标进程内执行 ==========
// 这个函数会被复制到目标进程中运行
void __stdcall Shellcode(MANUAL_MAP_DATA* pData) {
    if (!pData) return;

    BYTE* pBase = (BYTE*)pData->pBase;
    auto* pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    auto* pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    auto* pOptHeader = &pNtHeaders->OptionalHeader;

    // 1. 处理重定位
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

    // 2. 处理导入表
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

    // 3. 调用 DllMain
    if (pOptHeader->AddressOfEntryPoint) {
        pData->pDllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))
            (pBase + pOptHeader->AddressOfEntryPoint);
        pData->pDllMain((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
    }
}
// 用来计算 Shellcode 函数大小的标记
void ShellcodeEnd() {}

// ========== 辅助函数 ==========
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

// ========== 主函数：Manual Map 注入 ==========
bool ManualMap(HANDLE hProcess, const char* dllPath) {
    // 读取 DLL 文件
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cout << "无法打开 DLL 文件\n";
        return false;
    }
    size_t fileSize = file.tellg();
    file.seekg(0);
    std::vector<BYTE> rawDll(fileSize);
    file.read((char*)rawDll.data(), fileSize);
    file.close();

    // 解析 PE 头
    auto* pDosHeader = (PIMAGE_DOS_HEADER)rawDll.data();
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "无效的 PE 文件\n";
        return false;
    }
    auto* pNtHeaders = (PIMAGE_NT_HEADERS)(rawDll.data() + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "无效的 NT 签名\n";
        return false;
    }

    // 在目标进程分配内存
    LPVOID pTargetBase = VirtualAllocEx(hProcess, NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) {
        std::cout << "VirtualAllocEx 失败\n";
        return false;
    }
    std::cout << "目标进程分配地址: 0x" << std::hex << pTargetBase << "\n";

    // 写入 PE 头
    WriteProcessMemory(hProcess, pTargetBase, rawDll.data(),
        pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // 写入各节区
    auto* pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSection[i].SizeOfRawData) {
            WriteProcessMemory(hProcess,
                (BYTE*)pTargetBase + pSection[i].VirtualAddress,
                rawDll.data() + pSection[i].PointerToRawData,
                pSection[i].SizeOfRawData, NULL);
        }
    }

    // 准备注入数据
    MANUAL_MAP_DATA mapData = {};
    mapData.pLoadLibraryA = LoadLibraryA;
    mapData.pGetProcAddress = GetProcAddress;
    mapData.pBase = pTargetBase;

    // 写入 mapData
    LPVOID pMapData = VirtualAllocEx(hProcess, NULL, sizeof(mapData),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pMapData, &mapData, sizeof(mapData), NULL);

    // 写入 Shellcode
    size_t shellcodeSize = (DWORD64)ShellcodeEnd - (DWORD64)Shellcode;
    LPVOID pShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, pShellcode, (void*)Shellcode, shellcodeSize, NULL);

    // 创建远程线程执行 Shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pShellcode, pMapData, 0, NULL);
    if (!hThread) {
        std::cout << "CreateRemoteThread 失败\n";
        return false;
    }

    // 等待执行完成
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // 清理 shellcode 和 mapData（可选）
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);

    // 可选：擦除 PE 头，防止内存扫描
    BYTE zeros[0x1000] = {};
    WriteProcessMemory(hProcess, pTargetBase, zeros,
        pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

    std::cout << "Manual Map 注入成功！\n";
    return true;
}

int main() {
	std::string logPath = "C:\Users\27817\Desktop\logs";

    const wchar_t* targetProcess = L"qt_01.exe";  // ← 改成目标进程名
    const char* dllPath = "D:\\Users\\27817\\source\\repos\\dll_d01\\out\\build\\x64-release\\dll_d02.dll";             // ← 改成你的 DLL 路径

    DWORD pid = GetProcessIdByName(targetProcess);
    if (!pid) {
        std::cout << "找不到目标进程\n";
        return 1;
    }
    std::cout << "目标 PID: " << pid << "\n";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "OpenProcess 失败\n";
        return 1;
    }

    ManualMap(hProcess, dllPath);

    CloseHandle(hProcess);
    return 0;
}