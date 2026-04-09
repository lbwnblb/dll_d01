// dll_d01.cpp: 定义 DLL 应用程序的入口点。

#include "dll_d01.h"
#include <windows.h>
void messageBoxHello() {
    MessageBox(NULL, TEXT("Hello World!"), TEXT("DLL_PROCESS_ATTACH"), MB_OK | MB_ICONINFORMATION);
}

void messageBoxGoodbye() {
    MessageBox(NULL, TEXT("Goodbye World!"), TEXT("DLL_PROCESS_DETACH"), MB_OK | MB_ICONINFORMATION);
}
struct QListInternal {
    void* d;
    void** ptr;
    int64_t size;
};

typedef void* (*ChildrenFn)(void*);

ChildrenFn g_childrenFn = nullptr;

void InitChildrenFn(uintptr_t coreBase) {
    if (!g_childrenFn) {
        g_childrenFn = (ChildrenFn)GetProcAddress(
            (HMODULE)coreBase,
            "?children@QObject@@QEBAAEBV?$QList@PEAVQObject@@@@XZ"
        );
    }
}

void* GetChild(void* obj, int index) {
    QListInternal* list = (QListInternal*)g_childrenFn(obj);
    if (!list || index < 0 || index >= list->size) return nullptr;
    return (void*)list->ptr[index];
}

void* GetChildFromEnd(void* obj, int fromEnd) {
    QListInternal* list = (QListInternal*)g_childrenFn(obj);
    if (!list || list->size < fromEnd) return nullptr;
    return (void*)list->ptr[list->size - fromEnd];
}

void click_qt() {
    FILE* f = fopen("C:\\Users\\la\\Desktop\\log\\debug.txt", "w");

    uintptr_t coreBase = (uintptr_t)GetModuleHandle("Qt6Core.dll");
    uintptr_t widgetBase = (uintptr_t)GetModuleHandle("Qt6Widgets.dll");
    InitChildrenFn(coreBase);

    // 1. 获取顶层窗口
    typedef void (*TopLevelFn)(void* result);
    TopLevelFn topLevelFn = (TopLevelFn)GetProcAddress(
        (HMODULE)widgetBase,
        "?topLevelWidgets@QApplication@@SA?AV?$QList@PEAVQWidget@@@@XZ"
    );

    char listBuf[64] = { 0 };
    topLevelFn((void*)listBuf);
    QListInternal* topList = (QListInternal*)listBuf;
    void* topWindow = (void*)topList->ptr[0];

    fprintf(f, "topWindow: %p\n", topWindow);

    // 2. 按树结构导航到目标按钮
    void* panel = GetChild(topWindow, 2);       // vtable B500
    fprintf(f, "panel: %p\n", panel);

    void* subPanel = GetChild(panel, 2);  // 改成 2        // vtable B9F8
    fprintf(f, "subPanel: %p\n", subPanel);

    void* button = GetChildFromEnd(subPanel, 3); // 倒数第3个
    fprintf(f, "button: %p\n", button);

    if (!button) {
        fprintf(f, "button not found\n");
        fclose(f);
        return;
    }

    // 3. 取 d_ptr 并调用
    void* dPtr = *(void**)((uintptr_t)button + 0x8);
    fprintf(f, "dPtr: %p\n", dPtr);
    fflush(f);

    typedef void (*TargetFunc_t)(void* thisPtr);
    TargetFunc_t pFunc = (TargetFunc_t)(widgetBase + 0x125890);

    fprintf(f, "calling pFunc...\n");
    fflush(f);

    pFunc(dPtr);

    fprintf(f, "done\n");
    fclose(f);
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
