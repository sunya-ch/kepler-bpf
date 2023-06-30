/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8 for more details
 */
#include <linux/types.h>
#include <linux/sched.h>
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef struct process_metrics_t
{
    u64 cgroup_id;
    u64 pid;
    u64 process_run_time;
    u64 cpu_cycles;
    u64 cpu_instr;
    u64 cache_miss;
    u16 vec_nr[10]; // irq counter, 10 is the max number of irq vectors
    char comm[16];
} process_metrics_t;

typedef struct pid_time_t
{
    u32 pid;
    u32 cpu;
} pid_time_t;

#ifndef NUM_CPUS
#define NUM_CPUS 128
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef CPU_REF_FREQ
#define CPU_REF_FREQ 2500
#endif

#ifndef HZ
#define HZ 1000
#endif

#ifndef MAP_SIZE
#define MAP_SIZE 10240
#endif

// // Associate map with its key/value types
// #define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)	\
//         struct ____btf_map_##name {			\
//                 type_key key;				\
//                 type_val value;				\
//         };						\
//         struct ____btf_map_##name			\
//         __attribute__ ((section(".maps." #name), used))	\
//                 ____btf_map_##name = { }

// // Associate map with its key/value types for QUEUE/STACK map types
// #define BPF_ANNOTATE_KV_PAIR_QUEUESTACK(name, type_val)  \
//         struct ____btf_map_##name {     \
//                 type_val value;       \
//         };            \
//         struct ____btf_map_##name     \
//         __attribute__ ((section(".maps." #name), used)) \
//                 ____btf_map_##name = { }

// // Changes to the macro require changes in BFrontendAction classes
// #define BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, _flags) \
// struct _name##_table_t { \
//   _key_type key; \
//   _leaf_type leaf; \
//   _leaf_type * (*lookup) (_key_type *); \
//   _leaf_type * (*lookup_or_init) (_key_type *, _leaf_type *); \
//   _leaf_type * (*lookup_or_try_init) (_key_type *, _leaf_type *); \
//   int (*update) (_key_type *, _leaf_type *); \
//   int (*insert) (_key_type *, _leaf_type *); \
//   int (*delete) (_key_type *); \
//   void (*call) (void *, int index); \
//   void (*increment) (_key_type, ...); \
//   void (*atomic_increment) (_key_type, ...); \
//   int (*get_stackid) (void *, u64); \
//   void * (*sk_storage_get) (void *, void *, int); \
//   int (*sk_storage_delete) (void *); \
//   void * (*inode_storage_get) (void *, void *, int); \
//   int (*inode_storage_delete) (void *); \
//   void * (*task_storage_get) (void *, void *, int); \
//   int (*task_storage_delete) (void *); \
//   u32 max_entries; \
//   int flags; \
// }; \
// __attribute__((section("maps/" _table_type))) \
// struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
// BPF_ANNOTATE_KV_PAIR(_name, _key_type, _leaf_type)

// #define BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries) \
// BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, 0)

// // Identifier for current CPU used in perf_submit and perf_read
// // Prefer BPF_F_CURRENT_CPU flag, falls back to call helper for older kernel
// // Can be overridden from BCC
// #ifndef CUR_CPU_IDENTIFIER
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
// #define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
// #else
// #define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
// #endif
// #endif

// // Table for reading hw perf cpu counters
// #define BPF_PERF_ARRAY(_name, _max_entries) \
// struct _name##_table_t { \
//   int key; \
//   u32 leaf; \
//   /* counter = map.perf_read(index) */ \
//   u64 (*perf_read) (int); \
//   int (*perf_counter_value) (int, void *, u32); \
//   u32 max_entries; \
// }; \
// __attribute__((section("maps/perf_array"))) \
// struct _name##_table_t _name = { .max_entries = (_max_entries) }

// #define BPF_ARRAY1(_name) \
//   BPF_TABLE(BPF_MAP_TYPE_ARRAY, u32, u64, _name, 10240)
// #define BPF_ARRAY2(_name, _leaf_type) \
//   BPF_TABLE(BPF_MAP_TYPE_ARRAY, u32, _leaf_type, _name, 10240)
// #define BPF_ARRAY3(_name, _leaf_type, _size) \
//   BPF_TABLE(BPF_MAP_TYPE_ARRAY, u32, _leaf_type, _name, _size)

// // helper for default-variable macro function
// #define BPF_ARRAYX(_1, _2, _3, NAME, ...) NAME

// // Define an array function, some arguments optional
// // BPF_ARRAY(name, leaf_type=u64, size=10240)
// #define BPF_ARRAY(...) \
//   BPF_ARRAYX(__VA_ARGS__, BPF_ARRAY3, BPF_ARRAY2, BPF_ARRAY1)(__VA_ARGS__)
  

// #define BPF_HASH1(_name) \
//   BPF_TABLE("hash", u64, u64, _name, 10240)
// #define BPF_HASH2(_name, _key_type) \
//   BPF_TABLE("hash", _key_type, u64, _name, 10240)
// #define BPF_HASH3(_name, _key_type, _leaf_type) \
//   BPF_TABLE("hash", _key_type, _leaf_type, _name, 10240)
// #define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
//   BPF_TABLE(, _key_type, _leaf_type, _name, _size)

// // helper for default-variable macro function
// #define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME

// // Define a hash function, some arguments optional
// // BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
// #define BPF_HASH(...) \
//   BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3, BPF_HASH2, BPF_HASH1)(__VA_ARGS__)

// #ifndef CUR_CPU_IDENTIFIER
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
// #define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
// #else
// #define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
// #endif
// #endif

  //////////////////////////////

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct bpf_map_def SEC("maps") _name = {                        \
        .type = _type,                                              \
        .key_size = sizeof(_key_type),                              \
        .value_size = sizeof(_value_type),                          \
        .max_entries = _max_entries,                                \
    };

#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240);

#define BPF_ARRAY(_name, _leaf_type, _size) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _leaf_type, _size);

#define BPF_PERF_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, u32, _max_entries)

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	/* bpf helper functions like bpf_map_update_elem() below normally return
	 * long, but using int instead of long to store the result is a workaround
	 * to avoid incorrectly evaluating err in cases where the following criteria
	 * is met:
	 *     the architecture is 64-bit
	 *     the helper function return type is long
	 *     the helper function returns the value of a call to a bpf_map_ops func
	 *     the bpf_map_ops function return type is int
	 *     the compiler inlines the helper function
	 *     the compiler does not sign extend the result of the bpf_map_ops func
	 *
	 * if this criteria is met, at best an error can only be checked as zero or
	 * non-zero. it will not be possible to check for a negative value or a
	 * specific error value. this is because the sign bit would have been stuck
	 * at the 32nd bit of a 64-bit long int.
	 */
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -17)
		return 0;

	return bpf_map_lookup_elem(map, key);
}

struct sched_switch_args {
    unsigned long long pad;
    char prev_comm[TASK_COMM_LEN];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[TASK_COMM_LEN];
    int next_pid;
    int next_prio;
};

struct trace_event_raw_softirq {
    unsigned long softirq;
    unsigned long vec;
    unsigned long long ip;
};

  //////////////////////////////