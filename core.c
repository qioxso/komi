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
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/kfifo.h>
// --- 硬件断点头文件 ---
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include "comm.h"

#define DEVICE_NAME "shami"
#define MAX_LOG_SIZE 4096
#define RING_BUF_SIZE (1024 * 64)

// 全局日志缓冲区
static struct kfifo log_fifo;
static spinlock_t log_lock;
static wait_queue_head_t log_waitbuf;

// --- 辅助函数：格式化并写入日志 ---
static void log_to_user(const char* fmt, ...) {
    va_list args;
    char buf[512]; // 单条日志最大长度
    unsigned long flags;
    int len;

    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    // 1. dmesg 打印
    // printk(KERN_INFO "[Shami] %s", buf); 

    // 2. 写入用户态缓冲区
    spin_lock_irqsave(&log_lock, flags);
    if (kfifo_avail(&log_fifo) > len) {
        kfifo_in(&log_fifo, buf, len);
    }
    spin_unlock_irqrestore(&log_lock, flags);
    
    wake_up_interruptible(&log_waitbuf);
}

// =========================================================
// --- 内存读写功能 (Read/Write Memory) ---
// =========================================================
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

// =========================================================
// --- 硬件断点功能 (Hardware Watchpoint) ---
// =========================================================
struct my_watchpoint_ctx {
    struct list_head list;
    struct perf_event *bp;
    pid_t pid;
    uintptr_t addr;
};

static LIST_HEAD(watchpoint_list);
static DEFINE_MUTEX(watchpoint_lock);

static void watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    // 触发时的回调
    log_to_user("\n[WATCHPOINT HIT] Addr: 0x%lx\n", bp->attr.bp_addr);
    log_to_user("  Instruction PC: 0x%llx\n", regs->pc);
    log_to_user("  Caller LR (X30): 0x%llx\n", regs->regs[30]);
}

static int add_watchpoint(WATCHPOINT_CONFIG *wc) {
    struct perf_event_attr attr;
    struct perf_event *bp;
    struct task_struct *task;
    struct pid *pid_struct;
    struct my_watchpoint_ctx *ctx;
    int ret = 0;

    pid_struct = find_get_pid(wc->pid);
    if (!pid_struct) return -ESRCH;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) return -ESRCH;

    // 初始化属性
    hw_breakpoint_init(&attr);
    attr.bp_addr = wc->addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4; // 默认监控4字节
    if (wc->type == 1) attr.bp_type = HW_BREAKPOINT_W;
    else if (wc->type == 2) attr.bp_type = HW_BREAKPOINT_R;
    else attr.bp_type = HW_BREAKPOINT_W | HW_BREAKPOINT_R;

    // 注册断点
    bp = register_user_hw_breakpoint(&attr, watchpoint_handler, NULL, task);
    
    if (IS_ERR(bp)) {
        ret = PTR_ERR(bp);
        printk(KERN_ERR "[Shami] Register HWBP failed: %d\n", ret);
        put_task_struct(task);
        return ret;
    }

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        unregister_hw_breakpoint(bp);
        put_task_struct(task);
        return -ENOMEM;
    }
    ctx->bp = bp;
    ctx->pid = wc->pid;
    ctx->addr = wc->addr;

    mutex_lock(&watchpoint_lock);
    list_add(&ctx->list, &watchpoint_list);
    mutex_unlock(&watchpoint_lock);

    log_to_user("[Shami] Watchpoint ADDED at 0x%lx (PID: %d)\n", wc->addr, wc->pid);
    put_task_struct(task);
    return 0;
}

static int del_watchpoint(pid_t pid, uintptr_t addr) {
    struct my_watchpoint_ctx *ctx, *tmp;
    int found = 0;

    mutex_lock(&watchpoint_lock);
    list_for_each_entry_safe(ctx, tmp, &watchpoint_list, list) {
        if (ctx->pid == pid && ctx->addr == addr) {
            unregister_hw_breakpoint(ctx->bp);
            list_del(&ctx->list);
            kfree(ctx);
            found = 1;
            break;
        }
    }
    mutex_unlock(&watchpoint_lock);
    
    if (found) log_to_user("[Shami] Watchpoint REMOVED at 0x%lx\n", addr);
    return found ? 0 : -ENOENT;
}

static void clean_all_watchpoints(void) {
    struct my_watchpoint_ctx *ctx, *tmp;
    mutex_lock(&watchpoint_lock);
    list_for_each_entry_safe(ctx, tmp, &watchpoint_list, list) {
        unregister_hw_breakpoint(ctx->bp);
        list_del(&ctx->list);
        kfree(ctx);
    }
    mutex_unlock(&watchpoint_lock);
}

// =========================================================
// --- Uprobes 功能 (Hook / Monitor) ---
// =========================================================
struct my_uprobe_ctx {
    struct list_head list;
    struct uprobe_consumer consumer;
    struct inode *inode;
    loff_t offset;
    unsigned long vaddr;
    pid_t pid;
    uint32_t flags;
    int mod_count;
    REG_MOD_ITEM mods[MAX_REG_MODS];
};

static LIST_HEAD(uprobe_list);
static DEFINE_MUTEX(uprobe_lock);

static void format_user_stack(char *buf, int buf_len, struct pt_regs *regs) {
    unsigned long fp = regs->regs[29];
    unsigned long stack_content[2]; 
    int depth = 0;
    int used = strlen(buf);

    while (depth < 8 && fp != 0 && used < buf_len - 64) {
        if (fp & 0x7 || fp > 0x7ffffffff000) break;
        if (copy_from_user(stack_content, (void __user *)fp, sizeof(stack_content))) break;

        unsigned long next_fp = stack_content[0];
        unsigned long lr = stack_content[1];
        used += snprintf(buf + used, buf_len - used, "  #%02d LR: 0x%llx\n", depth, lr);

        if (next_fp == fp) break;
        fp = next_fp;
        depth++;
    }
}

static int my_uprobe_handler(struct uprobe_consumer *con, struct pt_regs *regs) {
    struct my_uprobe_ctx *ctx = container_of(con, struct my_uprobe_ctx, consumer);
    char *log_buf = NULL;
    int i;

    // 1. 修改寄存器
    if (ctx->flags & FLAG_MODIFY_REG) {
        for (i = 0; i < ctx->mod_count; i++) {
            int idx = ctx->mods[i].reg_index;
            uint64_t val = ctx->mods[i].value;
            if (idx >= 0 && idx <= 30) regs->regs[idx] = val;
            else if (idx == REG_IDX_SP) regs->sp = val;
            else if (idx == REG_IDX_PC) regs->pc = val;
        }
    }

    // 2. 日志捕获
    if (ctx->flags & (FLAG_ENABLE_LOG | FLAG_ENABLE_PRINTK)) {
        log_buf = kzalloc(MAX_LOG_SIZE, GFP_ATOMIC);
        if (log_buf) {
            int pos = 0;
            pos += snprintf(log_buf, MAX_LOG_SIZE, "\n[UPROBE] PID:%d Addr:0x%lx\n", ctx->pid, ctx->vaddr);
            pos += snprintf(log_buf + pos, MAX_LOG_SIZE - pos, "  PC : %016llx | SP : %016llx\n", regs->pc, regs->sp);
            for (i = 0; i <= 4; i++) { // 只打前5个寄存器省空间
                pos += snprintf(log_buf + pos, MAX_LOG_SIZE - pos, "  X%d: %016llx", i, regs->regs[i]);
            }
            snprintf(log_buf + pos, MAX_LOG_SIZE - pos, "\n");
            
            // 简单堆栈
            // format_user_stack(log_buf, MAX_LOG_SIZE, regs); // 可能会卡，视情况开启

            if (ctx->flags & FLAG_ENABLE_PRINTK) printk(KERN_INFO "%s", log_buf);
            if (ctx->flags & FLAG_ENABLE_LOG) log_to_user("%s", log_buf);
            
            kfree(log_buf);
        }
    }
    return 0;
}

static int resolve_addr_to_inode_offset(pid_t pid, unsigned long vaddr, struct inode **out_inode, loff_t *out_offset) {
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int ret = -EINVAL;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return -ESRCH;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) { put_pid(pid_struct); return -ESRCH; }
    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); put_pid(pid_struct); return -EINVAL; }

    mmap_read_lock(mm);
    vma = find_vma(mm, vaddr);
    if (vma && vma->vm_start <= vaddr && vma->vm_file) {
        *out_inode = file_inode(vma->vm_file);
        ihold(*out_inode);
        *out_offset = (vaddr - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
        ret = 0;
    } else ret = -EFAULT;
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
    if (!ctx) { iput(inode); return -ENOMEM; }

    ctx->consumer.handler = my_uprobe_handler;
    ctx->inode = inode;
    ctx->offset = offset;
    ctx->vaddr = uc->addr;
    ctx->pid = uc->pid;
    ctx->flags = uc->flags;
    ctx->mod_count = uc->mod_count;
    if (uc->mod_count > MAX_REG_MODS) ctx->mod_count = MAX_REG_MODS;
    memcpy(ctx->mods, uc->mods, sizeof(uc->mods));

    ret = uprobe_register(inode, offset, &ctx->consumer);
    if (ret) { iput(inode); kfree(ctx); return ret; }

    mutex_lock(&uprobe_lock);
    list_add(&ctx->list, &uprobe_list);
    mutex_unlock(&uprobe_lock);
    log_to_user("[Shami] Uprobe ADDED at 0x%lx\n", uc->addr);
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
            found = 1; break;
        }
    }
    mutex_unlock(&uprobe_lock);
    if (found) log_to_user("[Shami] Uprobe REMOVED at 0x%lx\n", vaddr);
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

// =========================================================
// --- 驱动入口 (IOCTL) ---
// =========================================================
static long shami_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    COPY_MEMORY cm;
    UPROBE_CONFIG uc;
    WATCHPOINT_CONFIG wc;
    LOG_BUFFER lb;
    void *kbuf = NULL;
    int ret = 0;
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;

    // 预处理数据拷贝
    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) return -EFAULT;
        kbuf = kmalloc(cm.size, GFP_KERNEL);
        if (!kbuf) return -ENOMEM;
    } else if (cmd == OP_ADD_UPROBE || cmd == OP_DEL_UPROBE) {
        if (copy_from_user(&uc, (void __user *)arg, sizeof(uc))) return -EFAULT;
    } else if (cmd == OP_ADD_WATCHPOINT || cmd == OP_DEL_WATCHPOINT) {
        if (copy_from_user(&wc, (void __user *)arg, sizeof(wc))) return -EFAULT;
    } else if (cmd == OP_GET_LOG) {
        if (copy_from_user(&lb, (void __user *)arg, sizeof(lb))) return -EFAULT;
    }

    switch (cmd) {
        case OP_READ_MEM:
            pid_struct = find_get_pid(cm.pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (read_memory_force(mm, cm.addr, kbuf, cm.size) == 0) {
                            if (copy_to_user(cm.buffer, kbuf, cm.size)) ret = -EFAULT;
                        } else ret = -EFAULT;
                        mmput(mm);
                    }
                    put_task_struct(task);
                }
                put_pid(pid_struct);
            }
            break;

        case OP_WRITE_MEM:
            if (copy_from_user(kbuf, cm.buffer, cm.size)) { ret = -EFAULT; break; }
            pid_struct = find_get_pid(cm.pid);
            if (pid_struct) {
                task = get_pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    mm = get_task_mm(task);
                    if (mm) {
                        if (write_memory_force(mm, cm.addr, kbuf, cm.size) == 0) ret = 0;
                        else ret = -EFAULT;
                        mmput(mm);
                    }
                    put_task_struct(task);
                }
                put_pid(pid_struct);
            }
            break;

        case OP_ADD_UPROBE: ret = add_uprobe(&uc); break;
        case OP_DEL_UPROBE: ret = del_uprobe(uc.pid, uc.addr); break;
        case OP_ADD_WATCHPOINT: ret = add_watchpoint(&wc); break;
        case OP_DEL_WATCHPOINT: ret = del_watchpoint(wc.pid, wc.addr); break;

        case OP_GET_LOG: {
            ret = wait_event_interruptible(log_waitbuf, !kfifo_is_empty(&log_fifo));
            if (ret != 0) break;
            
            kbuf = kmalloc(lb.size, GFP_KERNEL);
            if (!kbuf) { ret = -ENOMEM; break; }

            spin_lock_irq(&log_lock);
            int copied = kfifo_out(&log_fifo, kbuf, lb.size);
            spin_unlock_irq(&log_lock);

            if (copy_to_user(lb.buffer, kbuf, copied)) ret = -EFAULT;
            else {
                if (put_user(copied, &((LOG_BUFFER __user *)arg)->read_bytes)) ret = -EFAULT;
            }
        } break;
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
    if (kfifo_alloc(&log_fifo, RING_BUF_SIZE, GFP_KERNEL)) return -ENOMEM;
    spin_lock_init(&log_lock);
    init_waitqueue_head(&log_waitbuf);

    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) { kfifo_free(&log_fifo); return major; }
    shami_class = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(shami_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    
    printk(KERN_INFO "[Shami] Driver Loaded (RW/Uprobe/Watchpoint).\n");
    return 0;
}

static void __exit shami_exit(void) {
    clean_all_uprobes();
    clean_all_watchpoints(); // 记得清理断点
    
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
