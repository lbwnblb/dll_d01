// dll_d01.cpp: 定义 DLL 应用程序的入口点。

#include <windows.h>
#include "dll_d02_ali.h"
void messageBoxHello() {
    MessageBox(NULL, TEXT("Hello"), TEXT("Test"), MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
}
DWORD WINAPI ShowMsg(LPVOID) {
    MessageBox(NULL, TEXT("Hello!"), TEXT("Injected"), MB_OK | MB_SYSTEMMODAL);
    return 0;
}
void messageBoxGoodbye() {
    MessageBox(NULL, TEXT("Goodbye World!"), TEXT("DLL_PROCESS_DETACH"), MB_OK | MB_ICONINFORMATION);
}

// DLL 入口点函数
BOOL APIENTRY DllMain(
    HMODULE hModule,            // DLL 模块句柄
    DWORD  ul_reason_for_call,  // 调用原因
    LPVOID lpReserved           // 保留参数
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {   // ← 加花括号，否则编译报错

        //CreateThread(NULL, 0, ShowMsg, NULL, 0, NULL);
        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // DLL 被进程卸载时调用，弹出消息框
        messageBoxGoodbye();

        break;
    }
    return TRUE;
}

// 导出函数示例
extern "C" __declspec(dllexport) void SayHello()
{
    MessageBox(NULL, TEXT("Hello World from exported function!"), TEXT("SayHello"), MB_OK | MB_ICONINFORMATION);
}
