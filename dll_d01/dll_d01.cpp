// dll_d01.cpp: 定义 DLL 应用程序的入口点。

#include "dll_d01.h"
#include <windows.h>
void messageBoxHello() {
    MessageBox(NULL, TEXT("Hello World!"), TEXT("DLL_PROCESS_ATTACH"), MB_OK | MB_ICONINFORMATION);
}

void messageBoxGoodbye() {
    MessageBox(NULL, TEXT("Goodbye World!"), TEXT("DLL_PROCESS_DETACH"), MB_OK | MB_ICONINFORMATION);
}


void click_qt() {
    
    // 把 x64dbg 里看到的值直接硬编码
    typedef void (*TargetFunc_t)(void* thisPtr, void* param2);

    uintptr_t base = (uintptr_t)GetModuleHandle("Qt6Widgets.dll");
    TargetFunc_t pFunc = (TargetFunc_t)(base + 0x125C70);

    pFunc((void*)0x1FF68642AD0, (void*)0x1FF6B62A0B0);

}
DWORD WINAPI ThreadProc(LPVOID lpParam) {
    Sleep(1000); // 等一秒，确保程序完全加载
    click_qt();
    return 0;
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
        
        CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
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
