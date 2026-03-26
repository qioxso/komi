/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <syscall.h>
#include <kputils.h>
#include <ksyms.h>

#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include <asm-generic/unistd.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <common.h>
#include <ktypes.h>

KPM_NAME("amem-kpm");
KPM_VERSION("1.4.14");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("OpenAI");
KPM_DESCRIPTION("AMem process_vm hook bridge for Android process memory read/write");

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif

#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 271
#endif

#define AMEM_PAGE_MIN(a, b) ((a) < (b) ? (a) : (b))

struct iovec {
    void __user *iov_base;
    __kernel_size_t iov_len;
};

#define UIO_MAXIOV 1024
#define AMEM_ACCESS_VM_WRITE_FLAG 1u

int kfunc_def(sprintf)(char *buf, const char *fmt, ...);
unsigned long kfunc_def(_raw_spin_lock_irqsave)(raw_spinlock_t *lock);
void kfunc_def(_raw_spin_unlock_irqrestore)(raw_spinlock_t *lock, unsigned long flags);
void kfunc_def(__rcu_read_lock)(void);
void kfunc_def(__rcu_read_unlock)(void);
struct task_struct *kfunc_def(find_task_by_vpid)(pid_t pid);
pid_t kfunc_def(__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns);
struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);
void kfunc_def(mmput)(struct mm_struct *mm);
void *kfunc_def(vmalloc)(unsigned long size);
void *kfunc_def(vmalloc_noprof)(unsigned long size);
void kfunc_def(vfree)(const void *addr);
unsigned long kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, unsigned long n);
unsigned long kfunc_def(__arch_copy_from_user)(void *to, const void __user *from, unsigned long n);

u64 kvar_def(memstart_addr);

static int read_hook_installed = 0;
static int write_hook_installed = 0;
static uint64_t read_count = 0;
static uint64_t write_count = 0;

static uint64_t phys_offset = 0;
static uint64_t page_offset = 0;
static uint64_t page_shift_ = 12;
static uint64_t page_level_ = 4;
static uint64_t page_size_ = 4096;

#define AMEM_RECORD_STACK_DEPTH 8
#define AMEM_RECORD_EVENT_CAP 32
#define AMEM_RECORD_REARM_NONE   0u
#define AMEM_RECORD_REARM_LINEAR 1u
#define AMEM_RECORD_REARM_LINK   2u
#define AMEM_RECORD_PHASE_PRIMARY 0u
#define AMEM_RECORD_PHASE_REARM   1u
#define AMEM_SO_TRACE_EVENT_CAP 16
#define AMEM_SO_TRACE_DEFAULT_STEP_LIMIT 12u
#define AMEM_SO_TRACE_MAX_STEP_LIMIT AMEM_SO_TRACE_EVENT_CAP
#define AMEM_SO_TRACE_STATE_IDLE     0u
#define AMEM_SO_TRACE_STATE_ARMED    1u
#define AMEM_SO_TRACE_STATE_RUNNING  2u
#define AMEM_SO_TRACE_STATE_DONE     3u
#define AMEM_SO_TRACE_STATE_FAILED   4u
#define AMEM_SO_TRACE_STOP_NONE        0u
#define AMEM_SO_TRACE_STOP_MANUAL      1u
#define AMEM_SO_TRACE_STOP_MODULE_EXIT 2u
#define AMEM_SO_TRACE_STOP_STEP_LIMIT  3u
#define AMEM_SO_TRACE_STOP_ERROR       4u

#ifndef DBG_SPSR_SS
#define DBG_SPSR_SS (1UL << 21)
#endif

#ifndef DBG_HOOK_HANDLED
#define DBG_HOOK_HANDLED 0
#endif

#ifndef DBG_HOOK_ERROR
#define DBG_HOOK_ERROR 1
#endif

#define AMEM_PATCH_SLOT_SP     31u
#define AMEM_PATCH_SLOT_PC     32u
#define AMEM_PATCH_SLOT_PSTATE 33u
#define AMEM_PATCH_SLOT_COUNT  34u
#define AMEM_PATCH_BIT(slot)   (1ULL << (slot))

#define PERF_TYPE_BREAKPOINT 5
#define HW_BREAKPOINT_R      1
#define HW_BREAKPOINT_W      2
#define HW_BREAKPOINT_RW     (HW_BREAKPOINT_R | HW_BREAKPOINT_W)
#define HW_BREAKPOINT_X      4

#define PERF_ATTR_FLAG_DISABLED       (1ULL << 0)
#define PERF_ATTR_FLAG_EXCLUDE_USER   (1ULL << 4)
#define PERF_ATTR_FLAG_EXCLUDE_KERNEL (1ULL << 5)
#define PERF_ATTR_FLAG_EXCLUDE_HV     (1ULL << 6)

struct perf_event;
struct perf_sample_data;

typedef void (*perf_overflow_handler_t)(struct perf_event *bp,
                                        struct perf_sample_data *data,
                                        struct pt_regs *regs);

struct step_hook_local {
    struct list_head node;
    int (*fn)(struct pt_regs *regs, unsigned int esr);
};

struct perf_event_attr_local {
    u32 type;
    u32 size;
    u64 config;
    union {
        u64 sample_period;
        u64 sample_freq;
    };
    u64 sample_type;
    u64 read_format;
    u64 flags;
    union {
        u32 wakeup_events;
        u32 wakeup_watermark;
    };
    u32 bp_type;
    union {
        u64 bp_addr;
        u64 config1;
    };
    union {
        u64 bp_len;
        u64 config2;
    };
};

typedef struct perf_event *(*register_user_hw_breakpoint_fn)(
    struct perf_event_attr_local *attr,
    perf_overflow_handler_t triggered,
    void *context,
    struct task_struct *tsk);
typedef int (*modify_user_hw_breakpoint_fn)(
    struct perf_event *bp,
    struct perf_event_attr_local *attr);
typedef void (*unregister_hw_breakpoint_fn)(struct perf_event *bp);
typedef void (*user_single_step_fn)(struct task_struct *task);
typedef void (*register_step_hook_fn)(struct step_hook_local *hook);
typedef void (*unregister_step_hook_fn)(struct step_hook_local *hook);
typedef int (*access_process_vm_fn)(
    struct task_struct *tsk,
    unsigned long addr,
    void *buf,
    int len,
    unsigned int gup_flags);

struct amem_record_event {
    u64 seq;
    pid_t pid;
    pid_t tid;
    u64 bp_addr;
    u64 pc;
    u64 sp;
    u64 pstate;
    u64 regs[31];
    u64 patch_mask;
    s32 disable_rc;
    s32 rearm_rc;
    u32 auto_disabled;
    u32 patch_applied;
    u32 rearm_enabled;
    u32 stack_nr;
    unsigned long stack_entries[AMEM_RECORD_STACK_DEPTH];
};

struct amem_record_state {
    raw_spinlock_t lock;
    int armed;
    int auto_disable_on_hit;
    int auto_rearm_on_hit;
    int event_disabled;
    int rearm_event_disabled;
    pid_t pid;
    u64 addr;
    u64 rearm_addr;
    u32 len;
    u32 type;
    u32 rearm_mode;
    u32 phase;
    u64 patch_mask;
    u64 patch_values[AMEM_PATCH_SLOT_COUNT];
    u64 hit_seq;
    u64 dropped;
    u64 auto_disable_count;
    u64 auto_disable_failures;
    u64 rearm_count;
    u64 rearm_failures;
    u32 head;
    u32 count;
    struct perf_event *event;
    struct perf_event *rearm_event;
    struct amem_record_event events[AMEM_RECORD_EVENT_CAP];
};

struct amem_so_trace_event {
    u64 seq;
    pid_t pid;
    pid_t tid;
    u64 bp_addr;
    u64 pc;
    u64 sp;
    u64 pstate;
    u64 regs[31];
};

struct amem_so_trace_state {
    raw_spinlock_t lock;
    int armed;
    int running;
    pid_t pid;
    u64 entry_addr;
    u64 module_base;
    u64 module_end;
    u32 len;
    u32 step_limit;
    u32 state;
    u32 stop_reason;
    s32 last_rc;
    u64 hit_count;
    u64 dropped;
    u64 event_seq;
    u32 head;
    u32 count;
    struct perf_event *event;
    struct amem_so_trace_event events[AMEM_SO_TRACE_EVENT_CAP];
};

static register_user_hw_breakpoint_fn g_register_user_hw_breakpoint = NULL;
static modify_user_hw_breakpoint_fn g_modify_user_hw_breakpoint = NULL;
static unregister_hw_breakpoint_fn g_unregister_hw_breakpoint = NULL;
static user_single_step_fn g_user_enable_single_step = NULL;
static user_single_step_fn g_user_disable_single_step = NULL;
static register_step_hook_fn g_register_step_hook = NULL;
static unregister_step_hook_fn g_unregister_step_hook = NULL;
static access_process_vm_fn g_access_process_vm = NULL;
static int g_step_hook_registered = 0;
static struct amem_record_state g_record_state;
static struct amem_so_trace_state g_so_trace_state;
static int amem_so_trace_step_handler(struct pt_regs *regs, unsigned int esr);
static struct step_hook_local g_so_trace_step_hook = {
    .fn = amem_so_trace_step_handler,
};

static int amem_so_trace_supported(void)
{
    return (kver >= VERSION(5, 4, 0) &&
            g_register_user_hw_breakpoint &&
            g_unregister_hw_breakpoint &&
            g_user_enable_single_step &&
            g_user_disable_single_step &&
            g_register_step_hook &&
            g_unregister_step_hook) ? 1 : 0;
}

static int amem_is_legacy_kernel(void)
{
    return kver < VERSION(5, 4, 0) ? 1 : 0;
}

static int amem_record_handler_modify_supported(void)
{
    return 0;
}

static inline unsigned long amem_raw_lock_irqsave(raw_spinlock_t *lock)
{
    return kf__raw_spin_lock_irqsave(lock);
}

static inline void amem_raw_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    kf__raw_spin_unlock_irqrestore(lock, flags);
}

static inline void amem_raw_lock_init(raw_spinlock_t *lock)
{
    if (!lock) {
        return;
    }
    memset(lock, 0, sizeof(*lock));
}

static inline uint64_t phys_to_virt_(uint64_t phys)
{
    return ((unsigned long)(phys - phys_offset) | page_offset);
}

static inline uint64_t virt_to_phys_(uint64_t virt)
{
    if (kver > VERSION(5, 0, 0)) {
        return (virt - page_offset) + phys_offset;
    }
    return ((virt & ~page_offset) + phys_offset);
}

static uint64_t pgtable_to_tkpa(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift_ - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys_(pxd_va);
    uint64_t block_lv = 0;

    for (int64_t lv = 4 - page_level_; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift_ - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t pxd_entry_va = pxd_va + pxd_index * 8;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0x3) == 0x3) {
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift_)) - 1) << page_shift_);
        } else if ((pxd_desc & 0x3) == 0x1) {
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift_;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else {
            return 0;
        }

        pxd_va = phys_to_virt_(pxd_pa);
        if (block_lv) {
            break;
        }
    }

    {
        uint64_t left_bit = page_shift_ + (block_lv ? (3 - block_lv) * pxd_bits : 0);
        return pxd_pa + (va & ((1u << left_bit) - 1));
    }
}

static int pgtable_init(void)
{
    uint64_t tcr_el1 = 0;
    uint64_t t1sz = 0;
    uint64_t va_bits = 0;
    uint64_t tg1 = 0;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    t1sz = (tcr_el1 << 42) >> 58;
    va_bits = 64 - t1sz;
    tg1 = (tcr_el1 << 32) >> 62;

    page_shift_ = 12;
    if (tg1 == 1) {
        page_shift_ = 14;
    } else if (tg1 == 3) {
        page_shift_ = 16;
    }

    page_level_ = (va_bits - 4) / (page_shift_ - 3);

    if (kver > VERSION(5, 0, 0)) {
        page_offset = (-(UL(1) << va_bits));
    } else {
        page_offset = (UL(0xffffffffffffffff) - (UL(1) << (va_bits - 1)) + 1);
    }

    kvar_match(memstart_addr, NULL, 0);
    phys_offset = *kv_memstart_addr;
    page_size_ = 1ul << page_shift_;
    return 0;
}

static void amem_record_fill_attr(struct perf_event_attr_local *attr,
                                  u64 addr, u32 len, u32 type, int disabled)
{
    if (!attr) {
        return;
    }

    memset(attr, 0, sizeof(*attr));
    attr->type = PERF_TYPE_BREAKPOINT;
    attr->size = sizeof(*attr);
    attr->sample_period = 1;
    attr->wakeup_events = 1;
    attr->bp_type = type;
    attr->bp_addr = addr;
    attr->bp_len = len;
    attr->flags = PERF_ATTR_FLAG_EXCLUDE_KERNEL | PERF_ATTR_FLAG_EXCLUDE_HV;
    if (disabled) {
        attr->flags |= PERF_ATTR_FLAG_DISABLED;
    }
}

static const char *amem_so_trace_state_name(u32 state)
{
    switch (state) {
    case AMEM_SO_TRACE_STATE_IDLE:
        return "idle";
    case AMEM_SO_TRACE_STATE_ARMED:
        return "armed";
    case AMEM_SO_TRACE_STATE_RUNNING:
        return "running";
    case AMEM_SO_TRACE_STATE_DONE:
        return "done";
    case AMEM_SO_TRACE_STATE_FAILED:
        return "failed";
    default:
        return "unknown";
    }
}

static const char *amem_so_trace_stop_reason_name(u32 reason)
{
    switch (reason) {
    case AMEM_SO_TRACE_STOP_NONE:
        return "none";
    case AMEM_SO_TRACE_STOP_MANUAL:
        return "manual";
    case AMEM_SO_TRACE_STOP_MODULE_EXIT:
        return "module_exit";
    case AMEM_SO_TRACE_STOP_STEP_LIMIT:
        return "step_limit";
    case AMEM_SO_TRACE_STOP_ERROR:
        return "error";
    default:
        return "unknown";
    }
}

static void amem_so_trace_clear_locked(void)
{
    g_so_trace_state.hit_count = 0;
    g_so_trace_state.dropped = 0;
    g_so_trace_state.event_seq = 0;
    g_so_trace_state.head = 0;
    g_so_trace_state.count = 0;
    g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_NONE;
    g_so_trace_state.last_rc = 0;
    memset(g_so_trace_state.events, 0, sizeof(g_so_trace_state.events));
}

static void amem_so_trace_copy_event(struct amem_so_trace_event *dst,
                                     const struct amem_so_trace_event *src)
{
    u32 idx = 0;

    if (!dst || !src) {
        return;
    }

    dst->seq = src->seq;
    dst->pid = src->pid;
    dst->tid = src->tid;
    dst->bp_addr = src->bp_addr;
    dst->pc = src->pc;
    dst->sp = src->sp;
    dst->pstate = src->pstate;
    for (idx = 0; idx < 31; ++idx) {
        dst->regs[idx] = src->regs[idx];
    }
}

static void amem_so_trace_capture_regs(struct amem_so_trace_event *event,
                                       const struct pt_regs *regs)
{
    u32 idx = 0;

    if (!event || !regs) {
        return;
    }

    event->pc = regs->pc;
    event->sp = regs->sp;
    event->pstate = regs->pstate;
    for (idx = 0; idx < 31; ++idx) {
        event->regs[idx] = regs->regs[idx];
    }
}

static void amem_so_trace_append_event_locked(const struct amem_so_trace_event *event)
{
    u32 slot = 0;

    if (!event) {
        return;
    }

    slot = (g_so_trace_state.head + g_so_trace_state.count) % AMEM_SO_TRACE_EVENT_CAP;
    if (g_so_trace_state.count == AMEM_SO_TRACE_EVENT_CAP) {
        slot = g_so_trace_state.head;
        g_so_trace_state.head = (g_so_trace_state.head + 1) % AMEM_SO_TRACE_EVENT_CAP;
        g_so_trace_state.dropped++;
    } else {
        g_so_trace_state.count++;
    }
    amem_so_trace_copy_event(&g_so_trace_state.events[slot], event);
}

static int amem_so_trace_register_step_hook(void)
{
    if (g_step_hook_registered) {
        return 0;
    }
    if (!g_register_step_hook || !g_unregister_step_hook) {
        return -ENOSYS;
    }
    g_register_step_hook(&g_so_trace_step_hook);
    g_step_hook_registered = 1;
    return 0;
}

static int amem_so_trace_unregister_step_hook(void)
{
    if (!g_step_hook_registered) {
        return 0;
    }
    if (!g_unregister_step_hook) {
        return -ENOSYS;
    }
    g_unregister_step_hook(&g_so_trace_step_hook);
    g_step_hook_registered = 0;
    return 0;
}

static void amem_record_clear_locked(void)
{
    g_record_state.hit_seq = 0;
    g_record_state.dropped = 0;
    g_record_state.head = 0;
    g_record_state.count = 0;
    memset(g_record_state.events, 0, sizeof(g_record_state.events));
}

static void amem_record_patch_clear_locked(void)
{
    g_record_state.patch_mask = 0;
    memset(g_record_state.patch_values, 0, sizeof(g_record_state.patch_values));
}

static int amem_record_patch_slot_from_name(const char *name)
{
    int idx = 0;

    if (!name || !*name) {
        return -EINVAL;
    }
    if (!strcmp(name, "sp")) {
        return AMEM_PATCH_SLOT_SP;
    }
    if (!strcmp(name, "pc")) {
        return AMEM_PATCH_SLOT_PC;
    }
    if (!strcmp(name, "pstate")) {
        return AMEM_PATCH_SLOT_PSTATE;
    }
    if (name[0] == 'x' && name[1] >= '0' && name[1] <= '9') {
        idx = name[1] - '0';
        if (name[2] >= '0' && name[2] <= '9') {
            idx = idx * 10 + (name[2] - '0');
            if (name[3] != '\0') {
                return -EINVAL;
            }
        } else if (name[2] != '\0') {
            return -EINVAL;
        }
        if (idx >= 0 && idx < 31) {
            return idx;
        }
    }
    return -EINVAL;
}

static size_t amem_record_append_patch_lines(char *buf, size_t buf_size, size_t used,
                                             u64 patch_mask, const u64 *patch_values)
{
    u32 idx = 0;

    if (!buf || !patch_values || used >= buf_size) {
        return used;
    }

    used += scnprintf(buf + used, buf_size - used, "patch_mask=%llx\n",
                      (unsigned long long)patch_mask);
    if (!patch_mask) {
        return used;
    }

    for (idx = 0; idx < AMEM_PATCH_SLOT_COUNT && used < buf_size; ++idx) {
        if (!(patch_mask & AMEM_PATCH_BIT(idx))) {
            continue;
        }
        if (idx < 31) {
            used += scnprintf(buf + used, buf_size - used, "patch_x%u=%llx\n",
                              idx, (unsigned long long)patch_values[idx]);
        } else if (idx == AMEM_PATCH_SLOT_SP) {
            used += scnprintf(buf + used, buf_size - used, "patch_sp=%llx\n",
                              (unsigned long long)patch_values[idx]);
        } else if (idx == AMEM_PATCH_SLOT_PC) {
            used += scnprintf(buf + used, buf_size - used, "patch_pc=%llx\n",
                              (unsigned long long)patch_values[idx]);
        } else if (idx == AMEM_PATCH_SLOT_PSTATE) {
            used += scnprintf(buf + used, buf_size - used, "patch_pstate=%llx\n",
                              (unsigned long long)patch_values[idx]);
        }
    }

    return used;
}

static void amem_record_copy_event(struct amem_record_event *dst,
                                   const struct amem_record_event *src)
{
    u32 idx = 0;

    if (!dst || !src) {
        return;
    }

    dst->seq = src->seq;
    dst->pid = src->pid;
    dst->tid = src->tid;
    dst->bp_addr = src->bp_addr;
    dst->pc = src->pc;
    dst->sp = src->sp;
    dst->pstate = src->pstate;
    for (idx = 0; idx < 31; ++idx) {
        dst->regs[idx] = src->regs[idx];
    }
    dst->patch_mask = src->patch_mask;
    dst->disable_rc = src->disable_rc;
    dst->rearm_rc = src->rearm_rc;
    dst->auto_disabled = src->auto_disabled;
    dst->patch_applied = src->patch_applied;
    dst->rearm_enabled = src->rearm_enabled;
    dst->stack_nr = src->stack_nr;
    for (idx = 0; idx < AMEM_RECORD_STACK_DEPTH; ++idx) {
        dst->stack_entries[idx] = src->stack_entries[idx];
    }
}

static size_t amem_record_append_reg_lines(char *buf, size_t buf_size, size_t used,
                                           const struct amem_record_event *event)
{
    u32 base = 0;

    if (!buf || !event || used >= buf_size) {
        return used;
    }

    for (base = 4; base < 31 && used < buf_size; base += 4) {
        u32 idx = 0;
        u32 end = base + 4;
        if (end > 31) {
            end = 31;
        }

        used += scnprintf(buf + used, buf_size - used, "  regs[%02u-%02u]=", base, end - 1);
        for (idx = base; idx < end && used < buf_size; ++idx) {
            used += scnprintf(buf + used, buf_size - used,
                              "x%u:%llx%s",
                              idx,
                              (unsigned long long)event->regs[idx],
                              (idx + 1 < end) ? " " : "\n");
        }
    }

    return used;
}

static void amem_record_capture_regs(struct amem_record_event *event,
                                     const struct pt_regs *regs)
{
    u32 idx = 0;

    if (!event || !regs) {
        return;
    }

    event->pc = regs->pc;
    event->sp = regs->sp;
    event->pstate = regs->pstate;
    for (idx = 0; idx < 31; ++idx) {
        event->regs[idx] = regs->regs[idx];
    }
}

static u32 amem_record_apply_patch(struct pt_regs *regs,
                                   u64 patch_mask, const u64 *patch_values)
{
    u32 idx = 0;
    u32 applied = 0;

    if (!regs || !patch_values || !patch_mask) {
        return 0;
    }

    for (idx = 0; idx < 31; ++idx) {
        if (patch_mask & AMEM_PATCH_BIT(idx)) {
            regs->regs[idx] = patch_values[idx];
            applied = 1;
        }
    }
    if (patch_mask & AMEM_PATCH_BIT(AMEM_PATCH_SLOT_SP)) {
        regs->sp = patch_values[AMEM_PATCH_SLOT_SP];
        applied = 1;
    }
    if (patch_mask & AMEM_PATCH_BIT(AMEM_PATCH_SLOT_PC)) {
        regs->pc = patch_values[AMEM_PATCH_SLOT_PC];
        applied = 1;
    }
    if (patch_mask & AMEM_PATCH_BIT(AMEM_PATCH_SLOT_PSTATE)) {
        regs->pstate = patch_values[AMEM_PATCH_SLOT_PSTATE];
        applied = 1;
    }

    return applied;
}

static void amem_record_breakpoint_handler(struct perf_event *bp,
                                           struct perf_sample_data *data,
                                           struct pt_regs *regs)
{
    struct amem_record_event event;
    u64 patch_values[AMEM_PATCH_SLOT_COUNT];
    u64 patch_mask = 0;
    unsigned long flags = 0;
    u32 slot = 0;
    u32 idx = 0;

    (void)bp;
    (void)data;

    if (!regs) {
        return;
    }

    memset(&event, 0, sizeof(event));
    memset(patch_values, 0, sizeof(patch_values));
    flags = amem_raw_lock_irqsave(&g_record_state.lock);
    event.bp_addr = g_record_state.addr;
    event.pid = g_record_state.pid;
    event.tid = task_pid_vnr(current);
    patch_mask = g_record_state.patch_mask;
    for (idx = 0; idx < AMEM_PATCH_SLOT_COUNT; ++idx) {
        patch_values[idx] = g_record_state.patch_values[idx];
    }
    amem_record_capture_regs(&event, regs);
    event.patch_mask = patch_mask;
    event.patch_applied = amem_record_apply_patch(regs, patch_mask, patch_values);
    event.seq = ++g_record_state.hit_seq;
    slot = (g_record_state.head + g_record_state.count) % AMEM_RECORD_EVENT_CAP;
    if (g_record_state.count == AMEM_RECORD_EVENT_CAP) {
        slot = g_record_state.head;
        g_record_state.head = (g_record_state.head + 1) % AMEM_RECORD_EVENT_CAP;
        g_record_state.dropped++;
    } else {
        g_record_state.count++;
    }
    amem_record_copy_event(&g_record_state.events[slot], &event);
    amem_raw_unlock_irqrestore(&g_record_state.lock, flags);

    /*
     * Keep handler strictly non-blocking: do not touch perf breakpoint state
     * here. Step once to move past the trapped instruction.
     */
    regs->pstate |= DBG_SPSR_SS;
    if (g_user_enable_single_step) {
        g_user_enable_single_step(current);
    }
}

static int amem_record_disarm(void)
{
    struct perf_event *event = NULL;
    struct perf_event *rearm_event = NULL;
    unsigned long flags = 0;

    flags = amem_raw_lock_irqsave(&g_record_state.lock);
    event = g_record_state.event;
    rearm_event = g_record_state.rearm_event;
    g_record_state.event = NULL;
    g_record_state.rearm_event = NULL;
    g_record_state.armed = 0;
    g_record_state.auto_disable_on_hit = 0;
    g_record_state.auto_rearm_on_hit = 0;
    g_record_state.event_disabled = 0;
    g_record_state.rearm_event_disabled = 0;
    g_record_state.pid = 0;
    g_record_state.addr = 0;
    g_record_state.rearm_addr = 0;
    g_record_state.len = 0;
    g_record_state.type = 0;
    g_record_state.rearm_mode = AMEM_RECORD_REARM_NONE;
    g_record_state.phase = AMEM_RECORD_PHASE_PRIMARY;
    amem_raw_unlock_irqrestore(&g_record_state.lock, flags);

    if (event && g_unregister_hw_breakpoint) {
        g_unregister_hw_breakpoint(event);
    }
    if (rearm_event && g_unregister_hw_breakpoint) {
        g_unregister_hw_breakpoint(rearm_event);
    }
    return 0;
}

static int amem_record_arm_mode(pid_t pid, u64 addr, u32 len, u32 rearm_mode)
{
    struct perf_event_attr_local attr;
    struct task_struct *task = NULL;
    struct perf_event *event = NULL;
    int rc = 0;
    unsigned long flags = 0;

    if (!g_register_user_hw_breakpoint || !g_unregister_hw_breakpoint) {
        return -ENOSYS;
    }
    if (pid <= 0 || addr == 0) {
        return -EINVAL;
    }
    if (len != 1 && len != 2 && len != 4 && len != 8) {
        return -EINVAL;
    }
    if (rearm_mode != AMEM_RECORD_REARM_NONE) {
        return -EOPNOTSUPP;
    }
    rc = amem_record_disarm();
    if (rc < 0) {
        return rc;
    }

    amem_record_fill_attr(&attr, addr, len, HW_BREAKPOINT_X, 0);

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    event = g_register_user_hw_breakpoint(&attr, amem_record_breakpoint_handler, NULL, task);
    rcu_read_unlock();
    if (IS_ERR_OR_NULL(event)) {
        return event ? (int)PTR_ERR(event) : -EINVAL;
    }

    flags = amem_raw_lock_irqsave(&g_record_state.lock);
    g_record_state.event = event;
    g_record_state.rearm_event = NULL;
    g_record_state.armed = 1;
    g_record_state.auto_disable_on_hit = 0;
    g_record_state.auto_rearm_on_hit = 0;
    g_record_state.event_disabled = 0;
    g_record_state.rearm_event_disabled = 0;
    g_record_state.pid = pid;
    g_record_state.addr = addr;
    g_record_state.rearm_addr = 0;
    g_record_state.len = len;
    g_record_state.type = HW_BREAKPOINT_X;
    g_record_state.rearm_mode = AMEM_RECORD_REARM_NONE;
    g_record_state.phase = AMEM_RECORD_PHASE_PRIMARY;
    g_record_state.auto_disable_count = 0;
    g_record_state.auto_disable_failures = 0;
    g_record_state.rearm_count = 0;
    g_record_state.rearm_failures = 0;
    amem_record_clear_locked();
    amem_raw_unlock_irqrestore(&g_record_state.lock, flags);

    return rc;
}

static int amem_record_arm(pid_t pid, u64 addr, u32 len)
{
    return amem_record_arm_mode(pid, addr, len, AMEM_RECORD_REARM_NONE);
}

static size_t amem_record_dump(char *buf, size_t buf_size)
{
    struct amem_record_event snapshot[AMEM_RECORD_EVENT_CAP];
    u64 patch_values[AMEM_PATCH_SLOT_COUNT];
    u32 count = 0;
    u32 head = 0;
    u32 i = 0;
    u32 phase = AMEM_RECORD_PHASE_PRIMARY;
    u32 rearm_mode = AMEM_RECORD_REARM_NONE;
    u64 hit_seq = 0;
    u64 dropped = 0;
    u64 auto_disable_count = 0;
    u64 auto_disable_failures = 0;
    u64 patch_mask = 0;
    u64 rearm_count = 0;
    u64 rearm_failures = 0;
    int armed = 0;
    int auto_disable_on_hit = 0;
    int auto_rearm_on_hit = 0;
    int event_disabled = 0;
    int rearm_event_disabled = 0;
    pid_t pid = 0;
    u64 addr = 0;
    u64 rearm_addr = 0;
    u32 len = 0;
    size_t used = 0;
    unsigned long flags = 0;

    if (!buf || buf_size == 0) {
        return 0;
    }

    memset(patch_values, 0, sizeof(patch_values));
    flags = amem_raw_lock_irqsave(&g_record_state.lock);
    count = g_record_state.count;
    head = g_record_state.head;
    hit_seq = g_record_state.hit_seq;
    dropped = g_record_state.dropped;
    auto_disable_count = g_record_state.auto_disable_count;
    auto_disable_failures = g_record_state.auto_disable_failures;
    patch_mask = g_record_state.patch_mask;
    rearm_count = g_record_state.rearm_count;
    rearm_failures = g_record_state.rearm_failures;
    armed = g_record_state.armed;
    auto_disable_on_hit = g_record_state.auto_disable_on_hit;
    auto_rearm_on_hit = g_record_state.auto_rearm_on_hit;
    event_disabled = g_record_state.event_disabled;
    rearm_event_disabled = g_record_state.rearm_event_disabled;
    pid = g_record_state.pid;
    addr = g_record_state.addr;
    rearm_addr = g_record_state.rearm_addr;
    phase = g_record_state.phase;
    len = g_record_state.len;
    rearm_mode = g_record_state.rearm_mode;
    for (i = 0; i < AMEM_PATCH_SLOT_COUNT; ++i) {
        patch_values[i] = g_record_state.patch_values[i];
    }
    for (i = 0; i < count; ++i) {
        amem_record_copy_event(&snapshot[i],
                               &g_record_state.events[(head + i) % AMEM_RECORD_EVENT_CAP]);
    }
    amem_raw_unlock_irqrestore(&g_record_state.lock, flags);

    used += scnprintf(buf + used, buf_size - used,
                      "armed=%d\npid=%d\naddr=%llx\nrearm_addr=%llx\nrearm_mode=%u\nphase=%u\nlen=%u\nauto_disable_on_hit=%d\nauto_rearm_on_hit=%d\nevent_disabled=%d\nrearm_event_disabled=%d\nauto_disable_count=%llu\nauto_disable_failures=%llu\nrearm_count=%llu\nrearm_failures=%llu\nhits=%llu\ndropped=%llu\ncount=%u\n",
                      armed, pid, (unsigned long long)addr,
                      (unsigned long long)rearm_addr, rearm_mode, phase, len,
                      auto_disable_on_hit,
                      auto_rearm_on_hit,
                      event_disabled,
                      rearm_event_disabled,
                      (unsigned long long)auto_disable_count,
                      (unsigned long long)auto_disable_failures,
                      (unsigned long long)rearm_count,
                      (unsigned long long)rearm_failures,
                      (unsigned long long)hit_seq, (unsigned long long)dropped, count);
    used = amem_record_append_patch_lines(buf, buf_size, used, patch_mask, patch_values);

    for (i = 0; i < count && used < buf_size; ++i) {
        u32 s = 0;
        const struct amem_record_event *event = &snapshot[i];
        used += scnprintf(buf + used, buf_size - used,
                          "event[%u]=seq:%llu pid:%d tid:%d bp:%llx pc:%llx sp:%llx pstate:%llx x0:%llx x1:%llx x2:%llx x3:%llx patch_applied:%u patch_mask:%llx auto_disabled:%u disable_rc:%d rearm_enabled:%u rearm_rc:%d stack:%u\n",
                          i,
                          (unsigned long long)event->seq,
                          event->pid,
                          event->tid,
                          (unsigned long long)event->bp_addr,
                          (unsigned long long)event->pc,
                          (unsigned long long)event->sp,
                          (unsigned long long)event->pstate,
                          (unsigned long long)event->regs[0],
                          (unsigned long long)event->regs[1],
                          (unsigned long long)event->regs[2],
                          (unsigned long long)event->regs[3],
                          event->patch_applied,
                          (unsigned long long)event->patch_mask,
                          event->auto_disabled,
                          event->disable_rc,
                          event->rearm_enabled,
                          event->rearm_rc,
                          event->stack_nr);
        used = amem_record_append_reg_lines(buf, buf_size, used, event);
        for (s = 0; s < event->stack_nr && used < buf_size; ++s) {
            used += scnprintf(buf + used, buf_size - used,
                              "  stack[%u]=%lx\n", s, event->stack_entries[s]);
        }
    }

    if (used >= buf_size) {
        used = buf_size - 1;
    }
    buf[used] = '\0';
    return used;
}

static int amem_so_trace_step_handler(struct pt_regs *regs, unsigned int esr)
{
    struct amem_so_trace_event event;
    unsigned long flags = 0;
    u64 entry_addr = 0;
    u64 module_base = 0;
    u64 module_end = 0;
    pid_t pid = 0;
    pid_t tid = task_pid_vnr(current);
    u32 step_limit = 0;
    u32 state = AMEM_SO_TRACE_STATE_IDLE;
    u32 stop_reason = AMEM_SO_TRACE_STOP_NONE;
    int stop_now = 0;

    (void)esr;

    if (!regs) {
        return DBG_HOOK_ERROR;
    }

    flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
    state = g_so_trace_state.state;
    pid = g_so_trace_state.pid;
    entry_addr = g_so_trace_state.entry_addr;
    module_base = g_so_trace_state.module_base;
    module_end = g_so_trace_state.module_end;
    step_limit = g_so_trace_state.step_limit;
    amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);

    if (state != AMEM_SO_TRACE_STATE_RUNNING) {
        return DBG_HOOK_ERROR;
    }
    if (pid != tid) {
        flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
        if (g_so_trace_state.state == AMEM_SO_TRACE_STATE_RUNNING &&
            g_so_trace_state.pid != tid) {
            g_so_trace_state.running = 0;
            g_so_trace_state.state = AMEM_SO_TRACE_STATE_FAILED;
            g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_ERROR;
            g_so_trace_state.last_rc = -ESRCH;
        }
        amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);
        regs->pstate &= ~DBG_SPSR_SS;
        if (g_user_disable_single_step) {
            g_user_disable_single_step(current);
        }
        return DBG_HOOK_HANDLED;
    }

    memset(&event, 0, sizeof(event));
    event.pid = pid;
    event.tid = tid;
    event.bp_addr = entry_addr;
    amem_so_trace_capture_regs(&event, regs);

    if (event.pc < module_base || event.pc >= module_end) {
        stop_reason = AMEM_SO_TRACE_STOP_MODULE_EXIT;
    }

    flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
    event.seq = ++g_so_trace_state.event_seq;
    amem_so_trace_append_event_locked(&event);
    if (stop_reason == AMEM_SO_TRACE_STOP_NONE &&
        g_so_trace_state.count >= step_limit) {
        stop_reason = AMEM_SO_TRACE_STOP_STEP_LIMIT;
    }
    if (stop_reason != AMEM_SO_TRACE_STOP_NONE) {
        g_so_trace_state.running = 0;
        g_so_trace_state.state = AMEM_SO_TRACE_STATE_DONE;
        g_so_trace_state.stop_reason = stop_reason;
        g_so_trace_state.last_rc = 0;
        stop_now = 1;
    }
    amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);

    if (stop_now) {
        regs->pstate &= ~DBG_SPSR_SS;
        if (g_user_disable_single_step) {
            g_user_disable_single_step(current);
        }
    } else {
        regs->pstate |= DBG_SPSR_SS;
    }

    return DBG_HOOK_HANDLED;
}

static void amem_so_trace_breakpoint_handler(struct perf_event *bp,
                                             struct perf_sample_data *data,
                                             struct pt_regs *regs)
{
    struct amem_so_trace_event event;
    unsigned long flags = 0;
    pid_t tid = task_pid_vnr(current);
    u64 entry_addr = 0;
    u32 step_limit = 0;
    int start_step = 0;

    (void)bp;
    (void)data;

    memset(&event, 0, sizeof(event));

    flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
    entry_addr = g_so_trace_state.entry_addr;
    step_limit = g_so_trace_state.step_limit;
    amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);

    event.pid = tid;
    event.tid = tid;
    event.bp_addr = entry_addr;
    if (regs) {
        amem_so_trace_capture_regs(&event, regs);
    }

    flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
    g_so_trace_state.pid = tid;
    event.seq = ++g_so_trace_state.event_seq;
    amem_so_trace_append_event_locked(&event);
    g_so_trace_state.hit_count++;
    g_so_trace_state.armed = 0;
    if (!regs) {
        g_so_trace_state.running = 0;
        g_so_trace_state.state = AMEM_SO_TRACE_STATE_FAILED;
        g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_ERROR;
        g_so_trace_state.last_rc = -EINVAL;
    } else if (g_so_trace_state.count >= step_limit) {
        g_so_trace_state.running = 0;
        g_so_trace_state.state = AMEM_SO_TRACE_STATE_DONE;
        g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_STEP_LIMIT;
        g_so_trace_state.last_rc = 0;
    } else {
        g_so_trace_state.running = 1;
        g_so_trace_state.state = AMEM_SO_TRACE_STATE_RUNNING;
        g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_NONE;
        g_so_trace_state.last_rc = 0;
        start_step = 1;
    }
    amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);

    if (!regs) {
        return;
    }

    if (start_step) {
        regs->pstate |= DBG_SPSR_SS;
        if (g_user_enable_single_step) {
            g_user_enable_single_step(current);
        }
    } else {
        regs->pstate &= ~DBG_SPSR_SS;
        if (g_user_disable_single_step) {
            g_user_disable_single_step(current);
        }
    }
}

static int amem_so_trace_disarm(void)
{
    struct perf_event *event = NULL;
    unsigned long flags = 0;
    pid_t pid = 0;
    int need_disable_step = 0;
    int unregister_rc = 0;

    flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
    event = g_so_trace_state.event;
    pid = g_so_trace_state.pid;
    need_disable_step = g_so_trace_state.running;
    g_so_trace_state.event = NULL;
    if ((g_so_trace_state.armed || g_so_trace_state.running) &&
        g_so_trace_state.state != AMEM_SO_TRACE_STATE_DONE &&
        g_so_trace_state.state != AMEM_SO_TRACE_STATE_FAILED) {
        g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_MANUAL;
        g_so_trace_state.state = g_so_trace_state.hit_count
            ? AMEM_SO_TRACE_STATE_DONE
            : AMEM_SO_TRACE_STATE_IDLE;
        g_so_trace_state.last_rc = 0;
    }
    g_so_trace_state.armed = 0;
    g_so_trace_state.running = 0;
    amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);

    if (event && g_unregister_hw_breakpoint) {
        g_unregister_hw_breakpoint(event);
    }

    if (need_disable_step && g_user_disable_single_step && pid > 0) {
        struct task_struct *task = NULL;

        rcu_read_lock();
        task = find_task_by_vpid(pid);
        if (task) {
            g_user_disable_single_step(task);
        }
        rcu_read_unlock();
    }

    unregister_rc = amem_so_trace_unregister_step_hook();
    if (unregister_rc < 0) {
        return unregister_rc;
    }

    return 0;
}

static int amem_so_trace_arm(pid_t pid, u64 entry_addr,
                             u64 module_base, u64 module_end,
                             u32 step_limit, u32 len)
{
    struct perf_event_attr_local attr;
    struct task_struct *task = NULL;
    struct perf_event *event = NULL;
    unsigned long flags = 0;
    int rc = 0;

    if (kver < VERSION(5, 4, 0)) {
        return -EOPNOTSUPP;
    }
    if (!amem_so_trace_supported()) {
        return -ENOSYS;
    }
    if (pid <= 0 || entry_addr == 0 || module_base == 0 ||
        module_end <= module_base) {
        return -EINVAL;
    }
    if (entry_addr < module_base || entry_addr >= module_end) {
        return -EINVAL;
    }
    if (len != 1 && len != 2 && len != 4 && len != 8) {
        return -EINVAL;
    }
    if (step_limit == 0) {
        step_limit = AMEM_SO_TRACE_DEFAULT_STEP_LIMIT;
    }
    if (step_limit > AMEM_SO_TRACE_MAX_STEP_LIMIT) {
        return -EINVAL;
    }

    rc = amem_so_trace_register_step_hook();
    if (rc < 0) {
        return rc;
    }

    rc = amem_so_trace_disarm();
    if (rc < 0) {
        return rc;
    }

    amem_record_fill_attr(&attr, entry_addr, len, HW_BREAKPOINT_X, 0);

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    event = g_register_user_hw_breakpoint(&attr, amem_so_trace_breakpoint_handler, NULL, task);
    rcu_read_unlock();
    if (IS_ERR_OR_NULL(event)) {
        return event ? (int)PTR_ERR(event) : -EINVAL;
    }

    flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
    g_so_trace_state.event = event;
    g_so_trace_state.armed = 1;
    g_so_trace_state.running = 0;
    g_so_trace_state.pid = pid;
    g_so_trace_state.entry_addr = entry_addr;
    g_so_trace_state.module_base = module_base;
    g_so_trace_state.module_end = module_end;
    g_so_trace_state.len = len;
    g_so_trace_state.step_limit = step_limit;
    g_so_trace_state.state = AMEM_SO_TRACE_STATE_ARMED;
    g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_NONE;
    g_so_trace_state.last_rc = 0;
    amem_so_trace_clear_locked();
    amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);

    return 0;
}

static size_t amem_so_trace_dump(char *buf, size_t buf_size, int include_events)
{
    struct amem_so_trace_event snapshot[AMEM_SO_TRACE_EVENT_CAP];
    unsigned long flags = 0;
    u32 state = AMEM_SO_TRACE_STATE_IDLE;
    u32 stop_reason = AMEM_SO_TRACE_STOP_NONE;
    u32 step_limit = 0;
    u32 len = 0;
    u32 count = 0;
    u32 head = 0;
    u32 i = 0;
    s32 last_rc = 0;
    int armed = 0;
    int running = 0;
    pid_t pid = 0;
    u64 entry_addr = 0;
    u64 module_base = 0;
    u64 module_end = 0;
    u64 hit_count = 0;
    u64 dropped = 0;
    size_t used = 0;

    if (!buf || buf_size == 0) {
        return 0;
    }

    flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
    armed = g_so_trace_state.armed;
    running = g_so_trace_state.running;
    pid = g_so_trace_state.pid;
    entry_addr = g_so_trace_state.entry_addr;
    module_base = g_so_trace_state.module_base;
    module_end = g_so_trace_state.module_end;
    len = g_so_trace_state.len;
    step_limit = g_so_trace_state.step_limit;
    state = g_so_trace_state.state;
    stop_reason = g_so_trace_state.stop_reason;
    last_rc = g_so_trace_state.last_rc;
    hit_count = g_so_trace_state.hit_count;
    dropped = g_so_trace_state.dropped;
    count = g_so_trace_state.count;
    head = g_so_trace_state.head;
    for (i = 0; i < count; ++i) {
        amem_so_trace_copy_event(&snapshot[i],
                                 &g_so_trace_state.events[(head + i) % AMEM_SO_TRACE_EVENT_CAP]);
    }
    amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);

    used += scnprintf(buf + used, buf_size - used,
                      "armed=%d\nrunning=%d\nstate=%u\nstate_text=%s\nstop_reason=%u\nstop_reason_text=%s\npid=%d\nentry_addr=%llx\nmodule_base=%llx\nmodule_end=%llx\nlen=%u\nstep_limit=%u\nhits=%llu\ndropped=%llu\ncount=%u\nlast_rc=%d\n",
                      armed,
                      running,
                      state,
                      amem_so_trace_state_name(state),
                      stop_reason,
                      amem_so_trace_stop_reason_name(stop_reason),
                      pid,
                      (unsigned long long)entry_addr,
                      (unsigned long long)module_base,
                      (unsigned long long)module_end,
                      len,
                      step_limit,
                      (unsigned long long)hit_count,
                      (unsigned long long)dropped,
                      count,
                      last_rc);

    if (!include_events) {
        if (used >= buf_size) {
            used = buf_size - 1;
        }
        buf[used] = '\0';
        return used;
    }

    for (i = 0; i < count && used < buf_size; ++i) {
        const struct amem_so_trace_event *event = &snapshot[i];
        used += scnprintf(buf + used, buf_size - used,
                          "event[%u]=seq:%llu pid:%d tid:%d bp:%llx pc:%llx sp:%llx pstate:%llx x0:%llx x1:%llx x2:%llx x3:%llx x29:%llx x30:%llx\n",
                          i,
                          (unsigned long long)event->seq,
                          event->pid,
                          event->tid,
                          (unsigned long long)event->bp_addr,
                          (unsigned long long)event->pc,
                          (unsigned long long)event->sp,
                          (unsigned long long)event->pstate,
                          (unsigned long long)event->regs[0],
                          (unsigned long long)event->regs[1],
                          (unsigned long long)event->regs[2],
                          (unsigned long long)event->regs[3],
                          (unsigned long long)event->regs[29],
                          (unsigned long long)event->regs[30]);
    }

    if (used >= buf_size) {
        used = buf_size - 1;
    }
    buf[used] = '\0';
    return used;
}

static int copy_user_iovec(struct iovec **out_iov,
                           const struct iovec __user *user_iov,
                           unsigned long iovcnt)
{
    size_t bytes = 0;
    struct iovec *iov = NULL;

    if (!out_iov || !user_iov || iovcnt == 0 || iovcnt > UIO_MAXIOV) {
        return -EINVAL;
    }

    bytes = iovcnt * sizeof(struct iovec);
    if (kf_vmalloc) {
        iov = kf_vmalloc(bytes);
    } else if (kf_vmalloc_noprof) {
        iov = kf_vmalloc_noprof(bytes);
    }
    if (!iov) {
        return -ENOMEM;
    }

    if (kf___arch_copy_from_user(iov, user_iov, bytes) != 0) {
        if (kf_vfree) {
            kf_vfree(iov);
        }
        return -EFAULT;
    }

    *out_iov = iov;
    return 0;
}

static void free_user_iovec(struct iovec *iov)
{
    if (iov) {
        if (kf_vfree) {
            kf_vfree(iov);
        }
    }
}

static int copy_process_bytes_access_vm(struct task_struct *task,
                                        uint64_t remote_addr,
                                        void __user *local_buf,
                                        size_t len,
                                        int write)
{
    void *bounce = NULL;
    size_t copied = 0;
    size_t bounce_size = page_size_;
    int bounce_from_kmalloc = 0;
    int rc = 0;

    if (!task || !g_access_process_vm) {
        return -ENOSYS;
    }
    if (!kf___arch_copy_to_user || !kf___arch_copy_from_user) {
        return -ENOSYS;
    }
    if (!kf_vfree || (!kf_vmalloc && !kf_vmalloc_noprof)) {
        return -ENOSYS;
    }

    if (bounce_size == 0 || bounce_size > 65536u) {
        bounce_size = 4096;
    }

    if ((kf_kmalloc || kf___kmalloc) && kf_kfree) {
        bounce = kmalloc(bounce_size, GFP_KERNEL);
        if (bounce) {
            bounce_from_kmalloc = 1;
        }
    }
    if (!bounce && kf_vmalloc) {
        bounce = kf_vmalloc(bounce_size);
    } else if (!bounce && kf_vmalloc_noprof) {
        bounce = kf_vmalloc_noprof(bounce_size);
    }
    if (!bounce) {
        return -ENOMEM;
    }

    while (copied < len) {
        size_t chunk = AMEM_PAGE_MIN(len - copied, bounce_size);
        int bytes = 0;
        unsigned long left = 0;

        if (write) {
            left = kf___arch_copy_from_user(bounce,
                                            (const void __user *)((uintptr_t)local_buf + copied),
                                            chunk);
            if (left != 0) {
                rc = -EFAULT;
                break;
            }
        }

        bytes = g_access_process_vm(task,
                                    (unsigned long)(remote_addr + copied),
                                    bounce,
                                    (int)chunk,
                                    write ? AMEM_ACCESS_VM_WRITE_FLAG : 0u);
        if (bytes != (int)chunk) {
            rc = bytes < 0 ? bytes : -EFAULT;
            break;
        }

        if (!write) {
            left = kf___arch_copy_to_user((void __user *)((uintptr_t)local_buf + copied),
                                          bounce,
                                          chunk);
            if (left != 0) {
                rc = -EFAULT;
                break;
            }
        }

        copied += chunk;
    }

    if (bounce_from_kmalloc) {
        kfree(bounce);
    } else {
        kf_vfree(bounce);
    }
    return rc;
}

static int copy_process_bytes(pid_t pid, uint64_t remote_addr,
                              void __user *local_buf, size_t len, int write)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    uintptr_t pgd = 0;
    size_t copied = 0;

    task = kf_find_task_by_vpid(pid);
    if (!task) {
        return -ESRCH;
    }

    if (g_access_process_vm) {
        return copy_process_bytes_access_vm(task, remote_addr, local_buf, len, write);
    }

    if (!kf_get_task_mm || !kf_mmput) {
        return -ENOSYS;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        return -EINVAL;
    }

    pgd = *(uintptr_t *)((uintptr_t)mm + mm_struct_offset.pgd_offset);

    while (copied < len) {
        uint64_t va = remote_addr + copied;
        uint64_t pa = pgtable_to_tkpa(pgd, va);
        uint64_t page_off = va & (page_size_ - 1);
        size_t chunk = AMEM_PAGE_MIN(len - copied, page_size_ - page_off);
        void *kva = NULL;
        unsigned long left = 0;

        if (!pa) {
            kf_mmput(mm);
            return -EFAULT;
        }

        kva = (void *)phys_to_virt_(pa);
        if (!write) {
            left = kf___arch_copy_to_user((void __user *)((uintptr_t)local_buf + copied), kva, chunk);
        } else {
            left = kf___arch_copy_from_user(kva, (const void __user *)((uintptr_t)local_buf + copied), chunk);
        }

        if (left != 0) {
            kf_mmput(mm);
            return -EFAULT;
        }

        copied += chunk;
    }

    kf_mmput(mm);
    return 0;
}

static ssize_t do_process_vm_rw(pid_t pid,
                                const struct iovec __user *local_iov,
                                unsigned long liovcnt,
                                const struct iovec __user *remote_iov,
                                unsigned long riovcnt,
                                unsigned long flags,
                                int write)
{
    struct iovec *local = NULL;
    struct iovec *remote = NULL;
    ssize_t total = 0;
    unsigned long i = 0;
    unsigned long j = 0;
    int rc = 0;

    (void)flags;

    if (!kf_find_task_by_vpid || !kf___arch_copy_to_user || !kf___arch_copy_from_user) {
        return -ENOSYS;
    }
    if (!g_access_process_vm && (!kf_get_task_mm || !kf_mmput)) {
        return -ENOSYS;
    }

    if (!kf_find_task_by_vpid(pid)) {
        return -ESRCH;
    }

    rc = copy_user_iovec(&local, local_iov, liovcnt);
    if (rc < 0) {
        return rc;
    }

    rc = copy_user_iovec(&remote, remote_iov, riovcnt);
    if (rc < 0) {
        free_user_iovec(local);
        return rc;
    }

    while (i < liovcnt && j < riovcnt) {
        size_t local_len = local[i].iov_len;
        size_t remote_len = remote[j].iov_len;
        size_t chunk = AMEM_PAGE_MIN(local_len, remote_len);

        if (chunk > 0) {
            rc = copy_process_bytes(pid,
                                    (uint64_t)(uintptr_t)remote[j].iov_base,
                                    local[i].iov_base,
                                    chunk,
                                    write);
            if (rc < 0) {
                if (total == 0) {
                    total = rc;
                }
                break;
            }

            total += chunk;
            local[i].iov_base = (void __user *)((uintptr_t)local[i].iov_base + chunk);
            local[i].iov_len -= chunk;
            remote[j].iov_base = (void __user *)((uintptr_t)remote[j].iov_base + chunk);
            remote[j].iov_len -= chunk;
        }

        if (local[i].iov_len == 0) {
            i++;
        }
        if (remote[j].iov_len == 0) {
            j++;
        }
    }

    free_user_iovec(local);
    free_user_iovec(remote);

    if (write) {
        write_count++;
    } else {
        read_count++;
    }
    return total;
}

static void before_process_vm_readv(hook_fargs6_t *args, void *udata)
{
    pid_t pid = (pid_t)syscall_argn(args, 0);
    const struct iovec __user *local_iov = (typeof(local_iov))syscall_argn(args, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(args, 2);
    const struct iovec __user *remote_iov = (typeof(remote_iov))syscall_argn(args, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(args, 4);
    unsigned long flags = (unsigned long)syscall_argn(args, 5);

    (void)udata;
    args->ret = do_process_vm_rw(pid, local_iov, liovcnt, remote_iov, riovcnt, flags, 0);
    args->skip_origin = 1;
}

static void before_process_vm_writev(hook_fargs6_t *args, void *udata)
{
    pid_t pid = (pid_t)syscall_argn(args, 0);
    const struct iovec __user *local_iov = (typeof(local_iov))syscall_argn(args, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(args, 2);
    const struct iovec __user *remote_iov = (typeof(remote_iov))syscall_argn(args, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(args, 4);
    unsigned long flags = (unsigned long)syscall_argn(args, 5);

    (void)udata;
    args->ret = do_process_vm_rw(pid, local_iov, liovcnt, remote_iov, riovcnt, flags, 1);
    args->skip_origin = 1;
}

static int write_text_response(char *__user out_msg, int outlen, const char *buf)
{
    int len = 0;
    int cplen = 0;

    if (!out_msg || outlen <= 0 || !buf) {
        return -EINVAL;
    }

    len = strlen(buf);
    if (len >= outlen) {
        len = outlen - 1;
    }

    if (len < 0) {
        return -EINVAL;
    }

    cplen = compat_copy_to_user(out_msg, buf, len);
    if (cplen <= 0) {
        return -EFAULT;
    }

    {
        char zero = '\0';
        cplen = compat_copy_to_user(out_msg + len, &zero, 1);
        if (cplen <= 0) {
            return -EFAULT;
        }
    }
    return 0;
}

static size_t append_line(char *buf, size_t buf_size, size_t used, const char *text)
{
    if (!buf || !text || used >= buf_size) {
        return used;
    }
    used += scnprintf(buf + used, buf_size - used, "%s\n", text);
    return used;
}

static size_t append_symbol_line(char *buf, size_t buf_size, size_t used, const char *name)
{
    unsigned long sym = 0;

    if (!buf || !name || used >= buf_size) {
        return used;
    }

    sym = kallsyms_lookup_name(name);
    used += scnprintf(buf + used, buf_size - used, "%s=%lx\n", name, sym);
    return used;
}

static long amem_kpm_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err = 0;

    (void)args;
    (void)reserved;

    pr_info("amem-kpm init: event=%s\n", event ? event : "(null)");

    amem_raw_lock_init(&g_record_state.lock);
    amem_raw_lock_init(&g_so_trace_state.lock);
    kfunc_match(sprintf, NULL, 0);
    kfunc_match(_raw_spin_lock_irqsave, NULL, 0);
    kfunc_match(_raw_spin_unlock_irqrestore, NULL, 0);
    kfunc_match(__rcu_read_lock, NULL, 0);
    kfunc_match(__rcu_read_unlock, NULL, 0);
    kfunc_match(find_task_by_vpid, NULL, 0);
    kfunc_match(__task_pid_nr_ns, NULL, 0);
    kfunc_match(get_task_mm, NULL, 0);
    kfunc_match(mmput, NULL, 0);
    kfunc_match(vmalloc, NULL, 0);
    kfunc_match(vmalloc_noprof, NULL, 0);
    kfunc_match(vfree, NULL, 0);
    kfunc_match(__kmalloc, NULL, 0);
    kfunc_match(kmalloc, NULL, 0);
    kfunc_match(kfree, NULL, 0);
    kfunc_match(__arch_copy_to_user, NULL, 0);
    kfunc_match(__arch_copy_from_user, NULL, 0);

    g_register_user_hw_breakpoint = (register_user_hw_breakpoint_fn)(uintptr_t)
        kallsyms_lookup_name("register_user_hw_breakpoint");
    g_modify_user_hw_breakpoint = (modify_user_hw_breakpoint_fn)(uintptr_t)
        kallsyms_lookup_name("modify_user_hw_breakpoint");
    g_unregister_hw_breakpoint = (unregister_hw_breakpoint_fn)(uintptr_t)
        kallsyms_lookup_name("unregister_hw_breakpoint");
    g_access_process_vm = (access_process_vm_fn)(uintptr_t)
        kallsyms_lookup_name("access_process_vm");
    if (kver >= VERSION(5, 4, 0)) {
        g_user_enable_single_step = (user_single_step_fn)(uintptr_t)
            kallsyms_lookup_name("user_enable_single_step");
        g_user_disable_single_step = (user_single_step_fn)(uintptr_t)
            kallsyms_lookup_name("user_disable_single_step");
        g_register_step_hook = (register_step_hook_fn)(uintptr_t)
            kallsyms_lookup_name("register_user_step_hook");
        g_unregister_step_hook = (unregister_step_hook_fn)(uintptr_t)
            kallsyms_lookup_name("unregister_user_step_hook");
    } else {
        g_user_enable_single_step = NULL;
        g_user_disable_single_step = NULL;
        g_register_step_hook = NULL;
        g_unregister_step_hook = NULL;
    }

    if (!kf__raw_spin_lock_irqsave || !kf__raw_spin_unlock_irqrestore ||
        !kf___rcu_read_lock || !kf___rcu_read_unlock ||
        !kf_find_task_by_vpid || !kf___task_pid_nr_ns ||
        !kf___arch_copy_to_user || !kf___arch_copy_from_user) {
        pr_err("amem-kpm: missing required kernel symbols\n");
        return -ENOSYS;
    }
    if (!g_access_process_vm && (!kf_get_task_mm || !kf_mmput)) {
        pr_err("amem-kpm: missing access_process_vm and mm walk symbols\n");
        return -ENOSYS;
    }
    if (amem_is_legacy_kernel() && !g_access_process_vm) {
        pr_err("amem-kpm: legacy kernel requires access_process_vm\n");
        return -ENOSYS;
    }
    if (!kf_vfree || (!kf_vmalloc && !kf_vmalloc_noprof)) {
        pr_err("amem-kpm: missing vmalloc/vfree symbols\n");
        return -ENOSYS;
    }
    if (!g_access_process_vm) {
        pgtable_init();
    }

    err = inline_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, NULL, NULL);
    if (!err) {
        read_hook_installed = 1;
    } else {
        pr_err("amem-kpm: hook process_vm_readv failed: %d\n", err);
    }

    err = inline_hook_syscalln(__NR_process_vm_writev, 6, before_process_vm_writev, NULL, NULL);
    if (!err) {
        write_hook_installed = 1;
    } else {
        pr_err("amem-kpm: hook process_vm_writev failed: %d\n", err);
    }

    if (!read_hook_installed && !write_hook_installed) {
        return -EINVAL;
    }

    return 0;
}

static long amem_kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    char buf[4096];
    unsigned long sym = 0;

    if (!args || !strcmp(args, "status")) {
        sprintf(buf,
                "name=amem-kpm\n"
                "read_hook=%d\n"
                "write_hook=%d\n"
                "read_count=%llu\n"
                "write_count=%llu\n"
                "debug_record_mode=stable_exec_oneshot_patch_no_rearm\n"
                "debug_so_trace_mode=prototype_so_range_single_step_oneshot\n"
                "debug_interactive_mode=planned\n"
                "record_scope=single_task_vpid\n"
                "legacy_kernel=%d\n"
                "access_process_vm=%d\n"
                "record_handler_modify_supported=%d\n"
                "so_trace_supported=%d\n"
                "so_trace_armed=%d\n"
                "so_trace_running=%d\n"
                "so_trace_state=%u\n"
                "so_trace_stop_reason=%u\n"
                "so_trace_pid=%d\n"
                "so_trace_entry_addr=%llx\n"
                "so_trace_module_base=%llx\n"
                "so_trace_module_end=%llx\n"
                "so_trace_step_limit=%u\n"
                "so_trace_hits=%llu\n"
                "so_trace_count=%u\n"
                "record_armed=%d\n"
                "record_auto_disable_on_hit=%d\n"
                "record_auto_rearm_on_hit=%d\n"
                "record_event_disabled=%d\n"
                "record_rearm_event_disabled=%d\n"
                "record_pid=%d\n"
                "record_addr=%llx\n"
                "record_rearm_addr=%llx\n"
                "record_rearm_mode=%u\n"
                "record_phase=%u\n"
                "record_len=%u\n"
                "record_patch_mask=%llx\n"
                "record_auto_disable_count=%llu\n"
                "record_auto_disable_failures=%llu\n"
                "record_rearm_count=%llu\n"
                "record_rearm_failures=%llu\n"
                "record_hits=%llu\n"
                "record_dropped=%llu\n"
                "record_count=%u\n"
                "kernel=%x\n"
                "kp=%x\n",
                read_hook_installed,
                write_hook_installed,
                (unsigned long long)read_count,
                (unsigned long long)write_count,
                amem_is_legacy_kernel(),
                g_access_process_vm ? 1 : 0,
                amem_record_handler_modify_supported(),
                amem_so_trace_supported(),
                g_so_trace_state.armed,
                g_so_trace_state.running,
                g_so_trace_state.state,
                g_so_trace_state.stop_reason,
                g_so_trace_state.pid,
                (unsigned long long)g_so_trace_state.entry_addr,
                (unsigned long long)g_so_trace_state.module_base,
                (unsigned long long)g_so_trace_state.module_end,
                g_so_trace_state.step_limit,
                (unsigned long long)g_so_trace_state.hit_count,
                g_so_trace_state.count,
                g_record_state.armed,
                g_record_state.auto_disable_on_hit,
                g_record_state.auto_rearm_on_hit,
                g_record_state.event_disabled,
                g_record_state.rearm_event_disabled,
                g_record_state.pid,
                (unsigned long long)g_record_state.addr,
                (unsigned long long)g_record_state.rearm_addr,
                g_record_state.rearm_mode,
                g_record_state.phase,
                g_record_state.len,
                (unsigned long long)g_record_state.patch_mask,
                (unsigned long long)g_record_state.auto_disable_count,
                (unsigned long long)g_record_state.auto_disable_failures,
                (unsigned long long)g_record_state.rearm_count,
                (unsigned long long)g_record_state.rearm_failures,
                (unsigned long long)g_record_state.hit_seq,
                (unsigned long long)g_record_state.dropped,
                g_record_state.count,
                kver,
                kpver);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "reset")) {
        read_count = 0;
        write_count = 0;
        return write_text_response(out_msg, outlen, "ok");
    }

    if (!strcmp(args, "caps")) {
        sprintf(buf,
                "register_user_hw_breakpoint=%lx\n"
                "modify_user_hw_breakpoint=%lx\n"
                "unregister_hw_breakpoint=%lx\n"
                "register_user_step_hook=%lx\n"
                "unregister_user_step_hook=%lx\n"
                "register_step_hook=%lx\n"
                "unregister_step_hook=%lx\n"
                "user_enable_single_step=%lx\n"
                "user_disable_single_step=%lx\n"
                "access_process_vm=%lx\n"
                "ptrace_hbptriggered=%lx\n"
                "arch_ptrace=%lx\n",
                kallsyms_lookup_name("register_user_hw_breakpoint"),
                kallsyms_lookup_name("modify_user_hw_breakpoint"),
                kallsyms_lookup_name("unregister_hw_breakpoint"),
                kallsyms_lookup_name("register_user_step_hook"),
                kallsyms_lookup_name("unregister_user_step_hook"),
                kallsyms_lookup_name("register_step_hook"),
                kallsyms_lookup_name("unregister_step_hook"),
                kallsyms_lookup_name("user_enable_single_step"),
                kallsyms_lookup_name("user_disable_single_step"),
                kallsyms_lookup_name("access_process_vm"),
                kallsyms_lookup_name("ptrace_hbptriggered"),
                kallsyms_lookup_name("arch_ptrace"));
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "modes")) {
        size_t used = 0;

        used = append_line(buf, sizeof(buf), used, "mode.record_only=stable_exec_oneshot_patch_no_rearm");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.pause_target=0");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.scope=single_task_vpid");
        used = append_line(buf, sizeof(buf), used, "mode.process_vm.copy_backend=access_process_vm_preferred");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.auto_disable_on_hit=0_disabled_for_stability");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.linear_rearm=disabled_in_stable_build");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.return_rearm=disabled_in_stable_build");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.ret_loop_stack_snapshot=disabled_for_stability");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.view_registers=x0-x30/sp/pc/pstate");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.modify_registers=write_through_on_hit_no_pause");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.stack_snapshot=disabled_for_stability");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.trace=event_ring_dump");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.arm_cmd=record-arm <tid_or_pid> <addr> [len]");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.loop_cmd=record-arm-loop (unsupported_in_stable_build)");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.ret_loop_cmd=record-arm-ret-loop (unsupported_in_stable_build)");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.patch_set_cmd=record-patch-set <reg> <value>");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.patch_clear_cmd=record-patch-clear");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.read_cmd=record-read");
        used = append_line(buf, sizeof(buf), used, "mode.record_only.best_for=manual low-pause return patching");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace=prototype_so_range_single_step_oneshot");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.pause_target=0");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.scope=single_task_vpid_and_so_range");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.arm_cmd=trace-so-arm <tid_or_pid> <entry_addr> <module_base> <module_end> [step_limit] [len]");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.disarm_cmd=trace-so-disarm");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.clear_cmd=trace-so-clear");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.status_cmd=trace-so-status");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.read_cmd=trace-so-read");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.stop=leave_module_or_step_limit");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.min_kernel=5.4.0");
        used = append_line(buf, sizeof(buf), used, "mode.so_trace.best_for=bounded_so_flow_trace_without_ptrace");
        used = append_line(buf, sizeof(buf), used, "mode.interactive=planned");
        used = append_line(buf, sizeof(buf), used, "mode.interactive.pause_target=1");
        used = append_line(buf, sizeof(buf), used, "mode.interactive.view_registers=planned");
        used = append_line(buf, sizeof(buf), used, "mode.interactive.modify_registers=planned");
        used = append_line(buf, sizeof(buf), used, "mode.interactive.stack_snapshot=planned");
        used = append_line(buf, sizeof(buf), used, "mode.interactive.single_step=planned");
        used = append_line(buf, sizeof(buf), used, "mode.interactive.trace=planned");
        used = append_line(buf, sizeof(buf), used, "mode.interactive.best_for=debugging and state editing");
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "debugcaps")) {
        size_t used = 0;

        used = append_symbol_line(buf, sizeof(buf), used, "register_user_hw_breakpoint");
        used = append_symbol_line(buf, sizeof(buf), used, "modify_user_hw_breakpoint");
        used = append_symbol_line(buf, sizeof(buf), used, "unregister_hw_breakpoint");
        used = append_symbol_line(buf, sizeof(buf), used, "register_user_step_hook");
        used = append_symbol_line(buf, sizeof(buf), used, "unregister_user_step_hook");
        used = append_symbol_line(buf, sizeof(buf), used, "register_step_hook");
        used = append_symbol_line(buf, sizeof(buf), used, "unregister_step_hook");
        used = append_symbol_line(buf, sizeof(buf), used, "user_enable_single_step");
        used = append_symbol_line(buf, sizeof(buf), used, "user_disable_single_step");
        used = append_symbol_line(buf, sizeof(buf), used, "ptrace_hbptriggered");
        used = append_symbol_line(buf, sizeof(buf), used, "arch_ptrace");
        used = append_symbol_line(buf, sizeof(buf), used, "_raw_spin_lock_irqsave");
        used = append_symbol_line(buf, sizeof(buf), used, "_raw_spin_unlock_irqrestore");
        used = append_symbol_line(buf, sizeof(buf), used, "__rcu_read_lock");
        used = append_symbol_line(buf, sizeof(buf), used, "__rcu_read_unlock");
        used = append_symbol_line(buf, sizeof(buf), used, "task_pt_regs");
        used = append_symbol_line(buf, sizeof(buf), used, "find_task_by_vpid");
        used = append_symbol_line(buf, sizeof(buf), used, "__task_pid_nr_ns");
        used = append_symbol_line(buf, sizeof(buf), used, "get_task_mm");
        used = append_symbol_line(buf, sizeof(buf), used, "mmput");
        used = append_symbol_line(buf, sizeof(buf), used, "__arch_copy_to_user");
        used = append_symbol_line(buf, sizeof(buf), used, "__arch_copy_from_user");
        used = append_symbol_line(buf, sizeof(buf), used, "access_process_vm");
        used = append_symbol_line(buf, sizeof(buf), used, "stack_trace_save_tsk");
        used = append_symbol_line(buf, sizeof(buf), used, "save_stack_trace_tsk");
        used = append_symbol_line(buf, sizeof(buf), used, "stack_trace_save");
        used = append_symbol_line(buf, sizeof(buf), used, "wake_up_state");
        used = append_symbol_line(buf, sizeof(buf), used, "send_sig_info");
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strncmp(args, "record-arm-loop", 15)) {
        int pid = 0;
        unsigned long long addr = 0;
        unsigned int len = 4;
        int matched = sscanf(args + 15, "%d %llx %u", &pid, &addr, &len);
        int rc = 0;

        if (matched < 2) {
            return write_text_response(out_msg, outlen,
                                       "usage: record-arm-loop <tid_or_pid> <addr_hex> [len]");
        }

        rc = amem_record_arm_mode((pid_t)pid, (u64)addr, len, AMEM_RECORD_REARM_LINEAR);
        if (rc < 0) {
            if (rc == -EOPNOTSUPP) {
                scnprintf(buf, sizeof(buf),
                          "record-arm-loop failed rc=%d unsupported_in_stable_build",
                          rc);
            } else {
                scnprintf(buf, sizeof(buf), "record-arm-loop failed rc=%d", rc);
            }
            return write_text_response(out_msg, outlen, buf);
        }
        scnprintf(buf, sizeof(buf), "record-arm-loop ok pid=%d addr=%llx len=%u rearm=%llx",
                  pid, addr, len, addr + 4);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strncmp(args, "record-arm-ret-loop", 19)) {
        int pid = 0;
        unsigned long long addr = 0;
        unsigned int len = 4;
        int matched = sscanf(args + 19, "%d %llx %u", &pid, &addr, &len);
        int rc = 0;

        if (matched < 2) {
            return write_text_response(out_msg, outlen,
                                       "usage: record-arm-ret-loop <tid_or_pid> <ret_addr_hex> [len]");
        }

        rc = amem_record_arm_mode((pid_t)pid, (u64)addr, len, AMEM_RECORD_REARM_LINK);
        if (rc < 0) {
            if (rc == -EOPNOTSUPP) {
                scnprintf(buf, sizeof(buf),
                          "record-arm-ret-loop failed rc=%d unsupported_in_stable_build",
                          rc);
            } else {
                scnprintf(buf, sizeof(buf), "record-arm-ret-loop failed rc=%d", rc);
            }
            return write_text_response(out_msg, outlen, buf);
        }
        scnprintf(buf, sizeof(buf),
                  "record-arm-ret-loop ok pid=%d addr=%llx len=%u rearm=manual-after-hit pc-skip-ret",
                  pid, addr, len);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strncmp(args, "record-arm", 10)) {
        int pid = 0;
        unsigned long long addr = 0;
        unsigned int len = 4;
        int matched = sscanf(args + 10, "%d %llx %u", &pid, &addr, &len);
        int rc = 0;

        if (matched < 2) {
            return write_text_response(out_msg, outlen,
                                       "usage: record-arm <tid_or_pid> <addr_hex> [len]");
        }

        rc = amem_record_arm((pid_t)pid, (u64)addr, len);
        if (rc < 0) {
            if (rc == -EOPNOTSUPP) {
                scnprintf(buf, sizeof(buf),
                          "record-arm failed rc=%d unsupported_in_stable_build",
                          rc);
            } else {
                scnprintf(buf, sizeof(buf), "record-arm failed rc=%d", rc);
            }
            return write_text_response(out_msg, outlen, buf);
        }
        scnprintf(buf, sizeof(buf),
                  "record-arm ok pid=%d addr=%llx len=%u safe_no_rearm=1",
                  pid, addr, len);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strncmp(args, "record-patch-set", 16)) {
        char reg[16];
        long long value = 0;
        int slot = -EINVAL;
        int matched = 0;
        unsigned long flags = 0;

        memset(reg, 0, sizeof(reg));
        matched = sscanf(args + 16, "%15s %lli", reg, &value);
        if (matched < 2) {
            return write_text_response(out_msg, outlen,
                                       "usage: record-patch-set <reg> <value_auto_base>");
        }

        slot = amem_record_patch_slot_from_name(reg);
        if (slot < 0) {
            return write_text_response(out_msg, outlen,
                                       "record-patch-set failed: unsupported reg");
        }

        flags = amem_raw_lock_irqsave(&g_record_state.lock);
        g_record_state.patch_mask |= AMEM_PATCH_BIT((u32)slot);
        g_record_state.patch_values[slot] = (u64)value;
        amem_raw_unlock_irqrestore(&g_record_state.lock, flags);
        scnprintf(buf, sizeof(buf), "record-patch-set ok reg=%s value=%llx",
                  reg, (unsigned long long)((u64)value));
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "record-patch-clear")) {
        unsigned long flags = 0;
        flags = amem_raw_lock_irqsave(&g_record_state.lock);
        amem_record_patch_clear_locked();
        amem_raw_unlock_irqrestore(&g_record_state.lock, flags);
        return write_text_response(out_msg, outlen, "record-patch-clear ok");
    }

    if (!strcmp(args, "record-disarm")) {
        int rc = amem_record_disarm();
        if (rc < 0) {
            scnprintf(buf, sizeof(buf), "record-disarm failed rc=%d", rc);
            return write_text_response(out_msg, outlen, buf);
        }
        return write_text_response(out_msg, outlen, "record-disarm ok");
    }

    if (!strcmp(args, "record-clear")) {
        unsigned long flags = 0;
        flags = amem_raw_lock_irqsave(&g_record_state.lock);
        amem_record_clear_locked();
        amem_raw_unlock_irqrestore(&g_record_state.lock, flags);
        return write_text_response(out_msg, outlen, "record-clear ok");
    }

    if (!strcmp(args, "record-status")) {
        size_t used = 0;

        used += scnprintf(buf + used, sizeof(buf) - used,
                          "armed=%d\npid=%d\naddr=%llx\nrearm_addr=%llx\nrearm_mode=%u\nphase=%u\nlen=%u\nlegacy_kernel=%d\nhandler_modify_supported=%d\nauto_disable_on_hit=%d\nauto_rearm_on_hit=%d\nevent_disabled=%d\nrearm_event_disabled=%d\nauto_disable_count=%llu\nauto_disable_failures=%llu\nrearm_count=%llu\nrearm_failures=%llu\nhits=%llu\ndropped=%llu\ncount=%u\n",
                          g_record_state.armed,
                          g_record_state.pid,
                          (unsigned long long)g_record_state.addr,
                          (unsigned long long)g_record_state.rearm_addr,
                          g_record_state.rearm_mode,
                          g_record_state.phase,
                          g_record_state.len,
                          amem_is_legacy_kernel(),
                          amem_record_handler_modify_supported(),
                          g_record_state.auto_disable_on_hit,
                          g_record_state.auto_rearm_on_hit,
                          g_record_state.event_disabled,
                          g_record_state.rearm_event_disabled,
                          (unsigned long long)g_record_state.auto_disable_count,
                          (unsigned long long)g_record_state.auto_disable_failures,
                          (unsigned long long)g_record_state.rearm_count,
                          (unsigned long long)g_record_state.rearm_failures,
                          (unsigned long long)g_record_state.hit_seq,
                          (unsigned long long)g_record_state.dropped,
                          g_record_state.count);
        used = amem_record_append_patch_lines(buf, sizeof(buf), used,
                                              g_record_state.patch_mask,
                                              g_record_state.patch_values);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "record-read")) {
        amem_record_dump(buf, sizeof(buf));
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strncmp(args, "trace-so-arm", 12)) {
        int pid = 0;
        unsigned long long entry_addr = 0;
        unsigned long long module_base = 0;
        unsigned long long module_end = 0;
        unsigned int step_limit = AMEM_SO_TRACE_DEFAULT_STEP_LIMIT;
        unsigned int len = 4;
        int matched = sscanf(args + 12, "%d %llx %llx %llx %u %u",
                             &pid, &entry_addr, &module_base, &module_end,
                             &step_limit, &len);
        int rc = 0;

        if (matched < 4) {
            return write_text_response(out_msg, outlen,
                                       "usage: trace-so-arm <tid_or_pid> <entry_addr_hex> <module_base_hex> <module_end_hex> [step_limit] [len]");
        }

        rc = amem_so_trace_arm((pid_t)pid, (u64)entry_addr,
                               (u64)module_base, (u64)module_end,
                               step_limit, len);
        if (rc < 0) {
            if (rc == -EOPNOTSUPP) {
                scnprintf(buf, sizeof(buf),
                          "trace-so-arm failed rc=%d unsupported_kernel_need_5_4_plus",
                          rc);
            } else {
                scnprintf(buf, sizeof(buf), "trace-so-arm failed rc=%d", rc);
            }
            return write_text_response(out_msg, outlen, buf);
        }
        scnprintf(buf, sizeof(buf),
                  "trace-so-arm ok pid=%d entry=%llx module=[%llx,%llx) step_limit=%u len=%u",
                  pid, entry_addr, module_base, module_end, step_limit, len);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "trace-so-disarm")) {
        int rc = amem_so_trace_disarm();
        if (rc < 0) {
            scnprintf(buf, sizeof(buf), "trace-so-disarm failed rc=%d", rc);
            return write_text_response(out_msg, outlen, buf);
        }
        return write_text_response(out_msg, outlen, "trace-so-disarm ok");
    }

    if (!strcmp(args, "trace-so-clear")) {
        unsigned long flags = 0;

        flags = amem_raw_lock_irqsave(&g_so_trace_state.lock);
        if (g_so_trace_state.armed || g_so_trace_state.running) {
            amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);
            return write_text_response(out_msg, outlen, "trace-so-clear failed rc=-16");
        }
        g_so_trace_state.state = AMEM_SO_TRACE_STATE_IDLE;
        g_so_trace_state.stop_reason = AMEM_SO_TRACE_STOP_NONE;
        g_so_trace_state.last_rc = 0;
        amem_so_trace_clear_locked();
        amem_raw_unlock_irqrestore(&g_so_trace_state.lock, flags);
        return write_text_response(out_msg, outlen, "trace-so-clear ok");
    }

    if (!strcmp(args, "trace-so-status")) {
        amem_so_trace_dump(buf, sizeof(buf), 0);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "trace-so-read")) {
        amem_so_trace_dump(buf, sizeof(buf), 1);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strncmp(args, "sym:", 4)) {
        sym = kallsyms_lookup_name(args + 4);
        sprintf(buf, "%lx", sym);
        return write_text_response(out_msg, outlen, buf);
    }

    return write_text_response(out_msg, outlen,
                               "commands: status | reset | caps | debugcaps | modes | record-arm | record-arm-loop | record-arm-ret-loop | record-patch-set | record-patch-clear | record-disarm | record-clear | record-status | record-read | trace-so-arm | trace-so-disarm | trace-so-clear | trace-so-status | trace-so-read | sym:<symbol>");
}

static long amem_kpm_exit(void *__user reserved)
{
    int rc = 0;

    (void)reserved;

    if (read_hook_installed) {
        inline_unhook_syscalln(__NR_process_vm_readv, before_process_vm_readv, NULL);
        read_hook_installed = 0;
    }
    if (write_hook_installed) {
        inline_unhook_syscalln(__NR_process_vm_writev, before_process_vm_writev, NULL);
        write_hook_installed = 0;
    }
    rc = amem_record_disarm();
    if (rc < 0) {
        pr_err("amem-kpm exit blocked: record state busy rc=%d\n", rc);
        return rc;
    }
    rc = amem_so_trace_disarm();
    if (rc < 0) {
        pr_err("amem-kpm exit blocked: so trace state busy rc=%d\n", rc);
        return rc;
    }
    if (g_step_hook_registered && g_unregister_step_hook) {
        g_unregister_step_hook(&g_so_trace_step_hook);
        g_step_hook_registered = 0;
    }
    pr_info("amem-kpm exit\n");
    return 0;
}

KPM_INIT(amem_kpm_init);
KPM_CTL0(amem_kpm_control0);
KPM_EXIT(amem_kpm_exit);
