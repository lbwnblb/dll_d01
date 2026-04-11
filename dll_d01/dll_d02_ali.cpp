// dll_d02_ali.cpp — 修复版：取消注释 CreateThread + 添加文件日志

#include <windows.h>
#include <shlobj.h>
#include "dll_d02_ali.h"
#include <stdio.h>
#include <string>

void WriteLog(const char* msg) {
    // 动态获取桌面路径
    char desktopPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath)))
        return;
    std::string logDir = std::string(desktopPath) + "\\logs";
    CreateDirectoryA(logDir.c_str(), NULL);
    std::string logFile = logDir + "\\dll_d02_log.txt";
    FILE* f = fopen(logFile.c_str(), "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fflush(f);
        fclose(f);
    }
}

void messageBoxHello() {
    WriteLog("messageBoxHello called");
    MessageBox(NULL, TEXT("Hello"), TEXT("Test"), MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
    WriteLog("messageBoxHello returned");
}

DWORD WINAPI ShowMsg(LPVOID) {
    //WriteLog("ShowMsg thread started");
    MessageBox(NULL, TEXT("Hello!"), TEXT("Injected"), MB_OK | MB_SYSTEMMODAL);
    //WriteLog("ShowMsg thread returned");
    return 0;
}

void messageBoxGoodbye() {
    MessageBox(NULL, TEXT("Goodbye World!"), TEXT("DLL_PROCESS_DETACH"), MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        //WriteLog("DllMain: DLL_PROCESS_ATTACH entered");
        //CreateThread(NULL, 0, ShowMsg, NULL, 0, NULL);  // ← 已取消注释!
        //CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        //WriteLog("DllMain: CreateThread called");
        MessageBox(NULL, TEXT("Hello!"), TEXT("Injected"), MB_OK | MB_SYSTEMMODAL);
        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        messageBoxGoodbye();
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void SayHello()
{
    MessageBox(NULL, TEXT("Hello World from exported function!"), TEXT("SayHello"), MB_OK | MB_ICONINFORMATION);
}