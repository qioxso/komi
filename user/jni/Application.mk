# 指定支持的架构（王者荣耀目前主要是 arm64-v8a）
APP_ABI := arm64-v8a

# 指定支持的 Android 最低版本（process_vm_readv 需要较新版本）
APP_PLATFORM := android-24

# 使用 LLVM libc++ 静态库（保证兼容性）
APP_STL := c++_static

# 编译模式：发布版
APP_OPTIM := release


# 开启 C++ 异常支持 (关键修改！)
APP_CPPFLAGS += -fexceptions

# 开启 RTTI (可选，通常和异常一起开)
APP_CPPFLAGS += -frtti
