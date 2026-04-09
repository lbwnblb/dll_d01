# CMakeList.txt: dll_d01 的 CMake 项目，构建为 DLL 动态链接库。

# 将源代码添加到此项目的动态链接库。
add_library(dll_d01 SHARED "dll_d01.cpp" "dll_d01.h")
add_library(dll_d02_ali SHARED "dll_d02_ali.cpp" "dll_d02_ali.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET dll_d01 PROPERTY CXX_STANDARD 20)
endif()

# TODO: 如有需要，请添加测试并安装目标。
