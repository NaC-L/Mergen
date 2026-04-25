# vm_umin64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_umin64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_umin64_loop.ll`
- **Symbol:** `vm_umin64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_umin64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_umin64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0, n=1: only val=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, n=2 |
| 3 | RCX=7 | 7 | 7 | 7 | yes | x=7, n=8 |
| 4 | RCX=31 | 31 | 31 | 31 | yes | x=0x1F, n=32 max |
| 5 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF, n=32: i=0 val=255 stays minimum |
| 6 | RCX=51966 | 51966 | 51966 | 51966 | yes | x=0xCAFE, n=31 |
| 7 | RCX=3405691582 | 3405691582 | 3405691582 | 3405691582 | yes | x=0xCAFEBABE, n=31 |
| 8 | RCX=18446744073709551615 | 392661752437002822 | 392661752437002822 | 392661752437002822 | yes | max u64, n=32: small via xor |
| 9 | RCX=1311768467463790320 | 369637014058349209 | 369637014058349209 | 369637014058349209 | yes | 0x123...DEF0, n=17 |
| 10 | RCX=11400714819323198485 | 0 | 0 | 0 | yes | K (golden), n=22: K^K=0 at i=1 |

## Source

```c
/* PC-state VM running an i64 UNSIGNED-min reduction over a derived
 * sequence.
 *   n = (x & 0x1F) + 1;
 *   m = MAX_U64;
 *   for i in 0..n: { val = x ^ (i * K_golden); if (val < m) m = val; }
 *   return m;
 * Lift target: vm_umin64_loop_target.
 *
 * Distinct from vm_smax64_loop (signed-max via icmp sgt) and
 * vm_choosemax64_loop (per-iter ternary on fresh options): exercises
 * unsigned-min reduction via icmp ult + conditional-update accumulator.
 */
#include <stdio.h>
#include <stdint.h>

enum UmVmPc {
    UM_LOAD       = 0,
    UM_INIT       = 1,
    UM_LOOP_CHECK = 2,
    UM_LOOP_BODY  = 3,
    UM_LOOP_INC   = 4,
    UM_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_umin64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t m   = 0;
    int      pc  = UM_LOAD;

    while (1) {
        if (pc == UM_LOAD) {
            n  = (int)(x & 0x1Full) + 1;
            xx = x;
            m  = 0xFFFFFFFFFFFFFFFFull;
            pc = UM_INIT;
        } else if (pc == UM_INIT) {
            idx = 0;
            pc = UM_LOOP_CHECK;
        } else if (pc == UM_LOOP_CHECK) {
            pc = (idx < n) ? UM_LOOP_BODY : UM_HALT;
        } else if (pc == UM_LOOP_BODY) {
            uint64_t val = xx ^ ((uint64_t)idx * 0x9E3779B97F4A7C15ull);
            if (val < m) {
                m = val;
            }
            pc = UM_LOOP_INC;
        } else if (pc == UM_LOOP_INC) {
            idx = idx + 1;
            pc = UM_LOOP_CHECK;
        } else if (pc == UM_HALT) {
            return m;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_umin64(0xCAFE)=%llu vm_umin64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_umin64_loop_target(0xCAFEull),
           (unsigned long long)vm_umin64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
