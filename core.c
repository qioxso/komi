// core.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/uprobes.h>
#include <linux/wait.h>     // 等待队列
#include <linux/poll.h>
#include <linux/kfifo.h>    // 内核环形缓冲区

#include "comm.h"

#define DEVICE_NAME "shami"
#define MAX_LOG_SIZE 4096   // 单条日志最大长度
#define RING_BUF_SIZE (1024 * 64) // 总环形缓冲区大小 64KB

// --- 全局日志缓冲区 ---
// 使用 kfifo 实现环形缓冲区，方便从中断上下文写入，从进程上下文读取
static struct kfifo log_fifo;
static spinlock_t log_lock; // kfifo 的锁
static wait_queue_head_t log_waitbuf; // 等待队列，让读取操作阻塞等待数据

// --- 辅助函数：GUP 强力读取 ---
static int read_memory_force(struct mm_struct *mm, unsigned long addr, void *buffer, size_t size) {
    struct page *page;
    void *maddr;
    int res;
    size_t bytes_read = 0;
    
    while (bytes_read < size) {
        size_t offset = (addr + bytes_read) & ~PAGE_MASK;
        size_t bytes_to_copy = min(size - bytes_read, PAGE_SIZE - offset);

        res = get_user_pages_remote(mm, addr + bytes_read, 1, FOLL_FORCE, &page, NULL, NULL);
        if (res <= 0) return -1;

        maddr = kmap_atomic(page);
        memcpy(buffer + bytes_read, maddr + offset, bytes_to_copy);
        kunmap_atomic(maddr);
        
        put_page(page);
        bytes_read += bytes_to_copy;
    }
    return 0;
}

// --- 辅助函数：GUP 强力写入 ---
static int write_memory_force(struct mm_struct *mm, unsigned long addr, void *data, size_t size) {
    struct page *page;
    void *maddr;
    int res;
    size_t bytes_written = 0;

    while (bytes_written < size) {
        size_t offset = (addr + bytes_written) & ~PAGE_MASK;
        size_t bytes_to_copy = min(size - bytes_written, PAGE_SIZE - offset);

        res = get_user_pages_remote(mm, addr + bytes_written, 1, FOLL_WRITE | FOLL_FORCE, &page, NULL, NULL);
        if (res <= 0) return -1;

        maddr = kmap_atomic(page);
        memcpy(maddr + offset, data + bytes_written, bytes_to_copy);
        kunmap_atomic(maddr);
        
        set_page_dirty_lock(page);
        put_page(page);
        bytes_written += bytes_to_copy;
    }
    return 0;
}

// ---------------------------------------------------------
// --- Uprobes 相关功能 ---
// ---------------------------------------------------------

struct my_uprobe_ctx {
    struct list_head list;
    struct uprobe_consumer consumer;
    struct inode *inode;
    loff_t offset;
    unsigned long vaddr;
    pid_t pid;
    
    // 配置副本
    uint32_t flags;
    int mod_count;
    REG_MOD_ITEM mods[MAX_REG_MODS];
};

static LIST_HEAD(uprobe_list);
static DEFINE_MUTEX(uprobe_lock);

// --- 格式化用户态堆栈到缓冲区 ---
static void format_user_stack(char *buf, int buf_len, struct task_struct *task, struct pt_regs *regs) {
    unsigned long fp;
    unsigned long stack_content[2]; 
    int depth = 0;
    int max_depth = 8; // 稍微减少层数以免缓冲区溢出
    int used = 0;

    fp = regs->regs[29];
    used += snprintf(buf + used, buf_len - used, "--- User Stack ---\n");

    while (depth < max_depth && fp != 0 && used < buf_len - 1) {
        if (fp & 0x7 || fp > 0x7ffffffff000) break;

        // 注意：在中断上下文中 copy_from_user 可能会失败，
        // 这里的实现尽力而为。
        if (copy_from_user(stack_content, (void __user *)fp, sizeof(stack_content))) {
            used += snprintf(buf + used, buf_len - used, "#%02d: <Read Err>\n", depth);
            break;
        }

        unsigned long next_fp = stack_content[0];
        unsigned long lr = stack_content[1];

        used += snprintf(buf + used, buf_len - used, "#%02d: LR: 0x%llx\n", depth, lr);

        if (next_fp == fp) break;
        fp = next_fp;
        depth++;
    }
}

// --- 断点触发回调 ---
static int my_uprobe_handler(struct uprobe_consumer *con, struct pt_regs *regs) {
    struct my_uprobe_ctx *ctx = container_of(con, struct my_uprobe_ctx, consumer);
    char *log_buf = NULL;
    int i;
    unsigned long flags_lock;

    // 1. --- 寄存器修改逻辑 ---
    if (ctx->flags & FLAG_MODIFY_REG) {
        for (i = 0; i < ctx->mod_count; i++) {
            int idx = ctx->mods[i].reg_index;
            uint64_t val = ctx->mods[i].value;

            if (idx >= 0 && idx <= 30) {
                regs->regs[idx] = val; // 修改通用寄存器 X0-X30
                if (ctx->flags & FLAG_ENABLE_PRINTK) 
                    printk(KERN_INFO "[Shami] Mod X%d -> 0x%llx\n", idx, val);
            } else if (idx == REG_IDX_SP) {
                regs->sp = val;
            } else if (idx == REG_IDX_PC) {
                regs->pc = val;
            }
            // PSTATE 通常不建议随意修改，风险较大，此处略过
        }
    }

    // 2. --- 日志捕获逻辑 ---
    // 如果不需要日志也不需要打印，直接返回
    if (!(ctx->flags & (FLAG_ENABLE_LOG | FLAG_ENABLE_PRINTK))) {
        return 0;
    }

    // 分配临时缓冲区用于格式化字符串 (GFP_ATOMIC 因为在中断上下文)
    log_buf = kzalloc(MAX_LOG_SIZE, GFP_ATOMIC);
    if (!log_buf) return 0;

    int pos = 0;
    // 头部
    pos += snprintf(log_buf + pos, MAX_LOG_SIZE - pos, 
        "\n[HIT] PID:%d Addr:0x%lx\n", ctx->pid, ctx->vaddr);
    
    // 关键寄存器
    pos += snprintf(log_buf + pos, MAX_LOG_SIZE - pos, 
        "PC : %016llx | SP : %016llx\n", regs->pc, regs->sp);
    pos += snprintf(log_buf + pos, MAX_LOG_SIZE - pos, 
        "LR : %016llx | FP : %016llx\n", regs->regs[30], regs->regs[29]);

    // 通用寄存器 X0-X8 (打印部分常用的即可，避免buffer爆满)
    for (i = 0; i <= 8; i++) {
        pos += snprintf(log_buf + pos, MAX_LOG_SIZE - pos, 
            "X%02d: %016llx%s", i, regs->regs[i], (i+1)%3==0 ? "\n":" | ");
    }
    if (pos < MAX_LOG_SIZE) log_buf[pos++] = '\n';

    // 堆栈
    format_user_stack(log_buf + pos, MAX_LOG_SIZE - pos, current, regs);

    // 3. --- 输出处理 ---
    
    // 方式 A: dmesg 打印
    if (ctx->flags & FLAG_ENABLE_PRINTK) {
        printk(KERN_INFO "%s", log_buf);
    }

    // 方式 B: 写入环形缓冲区供用户态读取
    if (ctx->flags & FLAG_ENABLE_LOG) {
        spin_lock_irqsave(&log_lock, flags_lock);
        // kfifo_in 自动处理环形覆盖或截断，返回写入字节数
        kfifo_in(&log_fifo, log_buf, strlen(log_buf));
        spin_unlock_irqrestore(&log_lock, flags_lock);
        
        // 唤醒等待的读取进程
        wake_up_interruptible(&log_waitbuf);
    }

    kfree(log_buf);
    return 0;
}

static int resolve_addr_to_inode_offset(pid_t pid, unsigned long vaddr, struct inode **out_inode, loff_t *out_offset) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct file *vma_file;
    int ret = -EINVAL;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return -ESRCH;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        put_pid(pid_struct);
        return -EINVAL;
    }

    mmap_read_lock(mm);
    vma = find_vma(mm, vaddr);
    if (vma && vma->vm_start <= vaddr && vma->vm_file) {
        vma_file = vma->vm_file;
        *out_inode = file_inode(vma_file);
        ihold(*out_inode);
        *out_offset = (vaddr - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
        ret = 0;
    } else {
        ret = -EFAULT;
    }
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    return ret;
}

static int add_uprobe(UPROBE_CONFIG *uc) {
    struct my_uprobe_ctx *ctx;
    struct inode *inode = NULL;
    loff_t offset = 0;
    int ret;

    ret = resolve_addr_to_inode_offset(uc->pid, uc->addr, &inode, &offset);
    if (ret) return ret;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        iput(inode);
        return -ENOMEM;
    }

    ctx->consumer.handler = my_uprobe_handler;
    ctx->inode = inode;
    ctx->offset = offset;
    ctx->vaddr = uc->addr;
    ctx->pid = uc->pid;
    
    // --- 保存新配置 ---
    ctx->flags = uc->flags;
    ctx->mod_count = uc->mod_count;
    if (uc->mod_count > MAX_REG_MODS) ctx->mod_count = MAX_REG_MODS;
    memcpy(ctx->mods, uc->mods, sizeof(uc->mods));

    ret = uprobe_register(inode, offset, &ctx->consumer);
    if (ret) {
        iput(inode);
        kfree(ctx);
        return ret;
    }

    mutex_lock(&uprobe_lock);
    list_add(&ctx->list, &uprobe_list);
    mutex_unlock(&uprobe_lock);

    printk(KERN_INFO "[Shami] Uprobe Added. Flags: 0x%x, ModCount: %d\n", ctx->flags, ctx->mod_count);
    return 0;
}

static int del_uprobe(pid_t pid, unsigned long vaddr) {
    struct my_uprobe_ctx *ctx, *tmp;
    int found = 0;

    mutex_lock(&uprobe_lock);
    list_for_each_entry_safe(ctx, tmp, &uprobe_list, list) {
        if (ctx->pid == pid && ctx->vaddr == vaddr) {
            uprobe_unregister(ctx->inode, ctx->offset, &ctx->consumer);
            iput(ctx->inode);
            list_del(&ctx->list);
            kfree(ctx);
            found = 1;
            break;
        }
    }
    mutex_unlock(&uprobe_lock);
    return found ? 0 : -ENOENT;
}

static void clean_all_uprobes(void) {
    struct my_uprobe_ctx *ctx, *tmp;
    mutex_lock(&uprobe_lock);
    list_for_each_entry_safe(ctx, tmp, &uprobe_list, list) {
        uprobe_unregister(ctx->inode, ctx->offset, &ctx->consumer);
        iput(ctx->inode);
        list_del(&ctx->list);
        kfree(ctx);
    }
    mutex_unlock(&uprobe_lock);
}

// ---------------------------------------------------------
// --- IOCTL 主处理函数 ---
// ---------------------------------------------------------
static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    long ret = -EINVAL;
    COPY_MEMORY cm;
    UPROBE_CONFIG uc;
    LOG_BUFFER lb;
    void *kbuf = NULL;
    int copied;

    // 内存读写
    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -EFAULT;
        kbuf = kmalloc(cm.size, GFP_KERNEL);
        if (!kbuf) return -ENOMEM;
    }
    
    // Uprobe 配置
    if (cmd == OP_ADD_UPROBE || cmd == OP_DEL_UPROBE) {
        if (copy_from_user(&uc, (void __user *)arg, sizeof(uc))) return -EFAULT;
    }
    
    // 日志读取
    if (cmd == OP_GET_LOG) {
        if (copy_from_user(&lb, (void __user *)arg, sizeof(lb))) return -EFAULT;
    }

    switch (cmd) {
        case OP_READ_MEM: {
            pid_struct = find_get_pid(cm.pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (read_memory_force(mm, cm.addr, kbuf, cm.size) == 0) {
                            if (copy_to_user(cm.buffer, kbuf, cm.size)) ret = -EFAULT;
                            else ret = 0;
                        }
                        mmput(mm);
                    }
                    put_task_struct(task);
                }
                put_pid(pid_struct);
            }
        } break;

        case OP_WRITE_MEM: {
            if (copy_from_user(kbuf, cm.buffer, cm.size)) {
                kfree(kbuf); return -EFAULT;
            }
            pid_struct = find_get_pid(cm.pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (write_memory_force(mm, cm.addr, kbuf, cm.size) == 0) ret = 0;
                        mmput(mm);
                    }
                    put_task_struct(task);
                }
                put_pid(pid_struct);
            }
        } break;

        case OP_ADD_UPROBE:
            // 传递整个 uc 结构体，包含 flags 和 mods
            ret = add_uprobe(&uc);
            break;
            
        case OP_DEL_UPROBE:
            ret = del_uprobe(uc.pid, uc.addr);
            break;

        case OP_GET_LOG: {
            // 这是一个阻塞操作，如果没有日志，就等待
            // wait_event_interruptible 返回 0 表示条件满足，非0表示被信号中断
            ret = wait_event_interruptible(log_waitbuf, !kfifo_is_empty(&log_fifo));
            if (ret != 0) return ret; // 被信号打断

            // 分配临时内核缓冲
            kbuf = kmalloc(lb.size, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;

            spin_lock_irq(&log_lock); // 加锁读取
            ret = kfifo_out(&log_fifo, kbuf, lb.size);
            spin_unlock_irq(&log_lock);
            
            copied = ret;
            // 拷贝回用户态
            if (copy_to_user(lb.buffer, kbuf, copied)) {
                ret = -EFAULT;
            } else {
                // 更新实际读取大小
                if (put_user(copied, &((LOG_BUFFER __user *)arg)->read_bytes))
                    ret = -EFAULT;
                else 
                    ret = 0;
            }
        } break;
        
        default:
            ret = 0;
            break;
    }

    if (kbuf) kfree(kbuf);
    return ret;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = shami_ioctl,
    .compat_ioctl = shami_ioctl,
};

static int major;
static struct class *shami_class;

static int __init shami_init(void) {
    int ret;
    
    // 初始化日志环形缓冲区
    ret = kfifo_alloc(&log_fifo, RING_BUF_SIZE, GFP_KERNEL);
    if (ret) return ret;
    
    spin_lock_init(&log_lock);
    init_waitqueue_head(&log_waitbuf);

    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        kfifo_free(&log_fifo);
        return major;
    }
    shami_class = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(shami_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    
    printk(KERN_INFO "[Shami] Driver Loaded (Log Support: YES, RegMod: YES).\n");
    return 0;
}

static void __exit shami_exit(void) {
    clean_all_uprobes();
    
    device_destroy(shami_class, MKDEV(major, 0));
    class_destroy(shami_class);
    unregister_chrdev(major, DEVICE_NAME);
    
    kfifo_free(&log_fifo);
    printk(KERN_INFO "[Shami] Driver Unloaded.\n");
}

module_init(shami_init);
module_exit(shami_exit);
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
