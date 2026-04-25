# vm_oddcount64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_oddcount64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_oddcount64_loop.ll`
- **Symbol:** `vm_oddcount64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_oddcount64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_oddcount64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0, n=1: val=0 even |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, n=2: i=0 odd, i=1 even |
| 3 | RCX=2 | 1 | 1 | 1 | yes | x=2, n=3 |
| 4 | RCX=31 | 16 | 16 | 16 | yes | x=0x1F, n=32 max |
| 5 | RCX=255 | 16 | 16 | 16 | yes | x=0xFF, n=32 |
| 6 | RCX=51966 | 15 | 15 | 15 | yes | x=0xCAFE, n=31 |
| 7 | RCX=3405691582 | 15 | 15 | 15 | yes | x=0xCAFEBABE, n=31 |
| 8 | RCX=1311768467463790320 | 8 | 8 | 8 | yes | 0x123...DEF0, n=17 |
| 9 | RCX=18446744073709551615 | 16 | 16 | 16 | yes | max u64, n=32 |
| 10 | RCX=11400714819323198485 | 11 | 11 | 11 | yes | K (golden), n=22 |

## Source

```c
/* PC-state VM that counts how many values in a derived sequence are odd.
 *   count = 0; n = (x & 0x1F) + 1;
 *   for i in 0..n:
 *     val = x + i * K_golden
 *     if (val & 1): count++
 *   return count;
 * Returns count as i64 (low bits only).
 * Lift target: vm_oddcount64_loop_target.
 *
 * Distinct from vm_condsum64_loop (gated SUM accumulator on full i64
 * values) and the failed vm_dualcounter64_loop (two i64 counters cause
 * pseudo-stack promotion failure): single integer counter, gated by
 * parity bit-test, body uses i64 mul + add to compute val.
 */
#include <stdio.h>
#include <stdint.h>

enum OcVmPc {
    OC_LOAD       = 0,
    OC_INIT       = 1,
    OC_LOOP_CHECK = 2,
    OC_LOOP_BODY  = 3,
    OC_LOOP_INC   = 4,
    OC_HALT       = 5,
};

__declspec(noinline)
int vm_oddcount64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t xx    = 0;
    int      count = 0;
    int      pc    = OC_LOAD;

    while (1) {
        if (pc == OC_LOAD) {
            xx    = x;
            n     = (int)(x & 0x1Full) + 1;
            count = 0;
            pc = OC_INIT;
        } else if (pc == OC_INIT) {
            idx = 0;
            pc = OC_LOOP_CHECK;
        } else if (pc == OC_LOOP_CHECK) {
            pc = (idx < n) ? OC_LOOP_BODY : OC_HALT;
        } else if (pc == OC_LOOP_BODY) {
            uint64_t val = xx + (uint64_t)idx * 0x9E3779B97F4A7C15ull;
            if ((val & 1ull) != 0ull) {
                count = count + 1;
            }
            pc = OC_LOOP_INC;
        } else if (pc == OC_LOOP_INC) {
            idx = idx + 1;
            pc = OC_LOOP_CHECK;
        } else if (pc == OC_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_oddcount64(0xCAFE)=%d vm_oddcount64(0x1F)=%d\n",
           vm_oddcount64_loop_target(0xCAFEull),
           vm_oddcount64_loop_target(0x1Full));
    return 0;
}
```
