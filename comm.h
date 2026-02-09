// comm.h
#ifndef COMM_H
#define COMM_H

// 根据编译环境自动选择头文件
#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    #include <sys/types.h>
#endif

// 操作码定义
enum OPERATIONS {
    OP_INIT_KEY    = 0x800,
    OP_READ_MEM    = 0x801,
    OP_WRITE_MEM   = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_SET_API_ADDR= 0x804,
    OP_ADD_UPROBE  = 0x805,
    OP_DEL_UPROBE  = 0x806,
    // 新增：读取捕获的日志 (用于将寄存器信息传回用户态)
    OP_GET_LOG     = 0x807 
};

// 标志位定义
#define FLAG_ENABLE_LOG      (1 << 0) // 启用日志捕获（传回用户态）
#define FLAG_ENABLE_PRINTK   (1 << 1) // 启用 dmesg 打印 (调试用)
#define FLAG_MODIFY_REG      (1 << 2) // 启用寄存器修改

// 寄存器索引定义 (ARM64)
// 0-30: X0-X30, 31: SP, 32: PC, 33: PSTATE
#define REG_IDX_SP 31
#define REG_IDX_PC 32
#define REG_IDX_PSTATE 33

// 单个寄存器修改项
typedef struct _REG_MOD_ITEM {
    int reg_index;      // 0-30 for Xn, 31=SP, 32=PC
    uint64_t value;     // 要修改成的值
} REG_MOD_ITEM;

// 最大允许同时修改的寄存器数量
#define MAX_REG_MODS 8

// 内存拷贝结构体
typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY;

// Uprobe 配置结构体 (升级版)
typedef struct _UPROBE_CONFIG {
    pid_t pid;          // 目标进程PID
    uintptr_t addr;     // 目标虚拟地址
    
    uint32_t flags;     // 功能开关 (FLAG_*)
    
    // 寄存器修改配置
    int mod_count;                  // 需要修改的寄存器数量
    REG_MOD_ITEM mods[MAX_REG_MODS]; // 修改列表
} UPROBE_CONFIG;

// 日志读取结构体
typedef struct _LOG_BUFFER {
    char* buffer;       // 用户态缓冲区指针
    size_t size;        // 缓冲区大小
    size_t read_bytes;  // 实际读取到的字节数 (输出)
} LOG_BUFFER;

#endif // COMM_H
