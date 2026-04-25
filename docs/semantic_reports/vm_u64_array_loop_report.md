# vm_u64_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 8/8 equivalent
- **Source:** `testcases/rewrite_smoke/vm_u64_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_u64_array_loop.ll`
- **Symbol:** `vm_u64_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_u64_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_u64_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 6 | 6 | 6 | yes | seed=0: only constant additive part |
| 2 | RCX=1 | 16 | 16 | 16 | yes | seed=1 |
| 3 | RCX=7 | 76 | 76 | 76 | yes | seed=7 |
| 4 | RCX=4294967296 | 6 | 6 | 6 | yes | 0x1_00000000: only high i64 bits |
| 5 | RCX=3405691582 | 3992144754 | 3992144754 | 3992144754 | yes | 0xCAFEBABE |
| 6 | RCX=209937112161965 | 3992236744 | 3992236744 | 3992236744 | yes | 0xBEEFCAFEDEAD: shorter 48-bit input |
| 7 | RCX=18446744073709551615 | 4294967292 | 4294967292 | 4294967292 | yes | max u64: low32 = -4 u32 |
| 8 | RCX=1311768467463790320 | 190887270 | 190887270 | 190887270 | yes | 0x123456789ABCDEF0 |

## Source

```c
/* PC-state VM that fills a uint64_t[4] stack array with full 64-bit
 * values and accumulates them, returning the low 32 bits.
 * Lift target: vm_u64_array_loop_target.
 * Goal: cover an i64-element stack array (distinct from scalar-i64 cases
 * such as vm_int64_loop / vm_shift64_loop).  Symbolic seed and large i64
 * constants keep the lifter from collapsing the multiplies, and the final
 * 32-bit return matches the lifter's i64->i32 narrowing convention.
 */
#include <stdio.h>
#include <stdint.h>

enum U64VmPc {
    U64_LOAD       = 0,
    U64_INIT_FILL  = 1,
    U64_FILL_CHECK = 2,
    U64_FILL_BODY  = 3,
    U64_FILL_INC   = 4,
    U64_INIT_SUM   = 5,
    U64_SUM_CHECK  = 6,
    U64_SUM_BODY   = 7,
    U64_SUM_INC    = 8,
    U64_HALT       = 9,
};

__declspec(noinline)
unsigned int vm_u64_array_loop_target(uint64_t x) {
    uint64_t buf[4];
    int idx        = 0;
    uint64_t sum   = 0;
    uint64_t seed  = 0;
    int pc         = U64_LOAD;

    while (1) {
        if (pc == U64_LOAD) {
            seed = x;
            pc = U64_INIT_FILL;
        } else if (pc == U64_INIT_FILL) {
            idx = 0;
            pc = U64_FILL_CHECK;
        } else if (pc == U64_FILL_CHECK) {
            pc = (idx < 4) ? U64_FILL_BODY : U64_INIT_SUM;
        } else if (pc == U64_FILL_BODY) {
            buf[idx] = seed * (uint64_t)(idx + 1) + (uint64_t)idx * 0x100000001ull;
            pc = U64_FILL_INC;
        } else if (pc == U64_FILL_INC) {
            idx = idx + 1;
            pc = U64_FILL_CHECK;
        } else if (pc == U64_INIT_SUM) {
            idx = 0;
            pc = U64_SUM_CHECK;
        } else if (pc == U64_SUM_CHECK) {
            pc = (idx < 4) ? U64_SUM_BODY : U64_HALT;
        } else if (pc == U64_SUM_BODY) {
            sum = sum + buf[idx];
            pc = U64_SUM_INC;
        } else if (pc == U64_SUM_INC) {
            idx = idx + 1;
            pc = U64_SUM_CHECK;
        } else if (pc == U64_HALT) {
            return (unsigned int)(sum & 0xFFFFFFFFu);
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_u64_array_loop(0xCAFEBABE)=%u vm_u64_array_loop(0xFFFFFFFFFFFFFFFF)=%u\n",
           vm_u64_array_loop_target(0xCAFEBABEull),
           vm_u64_array_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
