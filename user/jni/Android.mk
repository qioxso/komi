LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# 生成的可执行文件名
LOCAL_MODULE := shami_test

# 你的 C++ 源文件名
LOCAL_SRC_FILES := test.cpp

# --- 核心修复 ---
# 在 Android.mk 中，不要用 APP_CPPFLAGS，要用 LOCAL_CPP_FEATURES
# 这行命令告诉 NDK：这个模块需要 C++ 异常 (try/catch) 和 RTTI 支持
LOCAL_CPP_FEATURES += exceptions rtti

# 包含路径（如果 comm.h 在当前目录，则不需要额外设置）
LOCAL_C_INCLUDES := $(LOCAL_PATH)

# 编译标志：开启 C++11 支持
LOCAL_CPPFLAGS := -std=c++11

# 静态链接 STL，避免在手机上找不到 .so 文件
LOCAL_LDLIBS := -llog

include $(BUILD_EXECUTABLE)
