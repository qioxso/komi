// comm.h
#ifndef COMM_H
#define COMM_H

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
    OP_MODULE_BASE = 0x803, // 保留
    OP_SET_API_ADDR= 0x804, // 保留
    OP_ADD_UPROBE  = 0x805, // 软件断点 (Hook)
    OP_DEL_UPROBE  = 0x806,
    OP_GET_LOG     = 0x807, // 读取日志
    OP_ADD_WATCHPOINT = 0x808, // 硬件断点 (Watchpoint)
    OP_DEL_WATCHPOINT = 0x809
};

// 标志位 (Uprobe用)
#define FLAG_ENABLE_LOG      (1 << 0)
#define FLAG_ENABLE_PRINTK   (1 << 1)
#define FLAG_MODIFY_REG      (1 << 2)

// 寄存器索引
#define REG_IDX_SP 31
#define REG_IDX_PC 32
#define REG_IDX_PSTATE 33

#define MAX_REG_MODS 8

// 结构体定义
typedef struct _REG_MOD_ITEM {
    int reg_index;
    uint64_t value;
} REG_MOD_ITEM;

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY;

typedef struct _UPROBE_CONFIG {
    pid_t pid;
    uintptr_t addr;
    uint32_t flags;
    int mod_count;
    REG_MOD_ITEM mods[MAX_REG_MODS];
} UPROBE_CONFIG;

typedef struct _LOG_BUFFER {
    char* buffer;
    size_t size;
    size_t read_bytes;
} LOG_BUFFER;

// --- 新增：硬件断点配置 ---
typedef struct _WATCHPOINT_CONFIG {
    pid_t pid;          // 目标进程PID
    uintptr_t addr;     // 监控地址
    int type;           // 1=Write(写), 2=Read(读), 3=RW(读写)
    int len;            // 监控长度 (通常为4)
} WATCHPOINT_CONFIG;

#endif
