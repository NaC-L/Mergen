# vm_maxrun64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_maxrun64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_maxrun64_loop.ll`
- **Symbol:** `vm_maxrun64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_maxrun64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_maxrun64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: no 1-bits |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: single 1-bit |
| 3 | RCX=255 | 8 | 8 | 8 | yes | x=0xFF: 8 consecutive |
| 4 | RCX=4080 | 8 | 8 | 8 | yes | x=0x0FF0: 8 in middle |
| 5 | RCX=16777215 | 24 | 24 | 24 | yes | x=0xFFFFFF: 24-run at low |
| 6 | RCX=51966 | 7 | 7 | 7 | yes | x=0xCAFE: 0xFE has 7 consec ones |
| 7 | RCX=3405691582 | 7 | 7 | 7 | yes | x=0xCAFEBABE: max run 7 |
| 8 | RCX=18446744073709551615 | 64 | 64 | 64 | yes | max u64: all 64 |
| 9 | RCX=11400714819323198485 | 7 | 7 | 7 | yes | K (golden): 7 |
| 10 | RCX=12297829382473034410 | 1 | 1 | 1 | yes | 0xAAAA...AAAA: alternating, max 1 |

## Source

```c
/* PC-state VM finding the longest run of consecutive 1-bits anywhere in
 * a uint64_t.
 *   max_run = 0; cur = 0;
 *   for i in 0..64:
 *     if ((x >> i) & 1):
 *       cur++;
 *       if (cur > max_run) max_run = cur;
 *     else:
 *       cur = 0;
 *   return max_run;
 * 64-trip fixed loop with TWO counters (max_run, cur) where ONE branch
 * conditionally updates max_run AFTER incrementing cur, and the OTHER
 * branch resets cur.  This is the documented "single-slot dual-update"
 * shape (max_run on one branch, cur reset on the other).
 *
 * Lift target: vm_maxrun64_loop_target.
 *
 * Distinct from vm_trailingones64_loop (only trailing run): scans whole
 * input and keeps a running max-of-runs.  Two i64 counter slots updated
 * in MUTUALLY-EXCLUSIVE branches but ONE slot is conditional max-update
 * (single-slot vs dual-slot mutex).
 */
#include <stdio.h>
#include <stdint.h>

enum MrVmPc {
    MR_LOAD       = 0,
    MR_INIT       = 1,
    MR_LOOP_CHECK = 2,
    MR_LOOP_BODY  = 3,
    MR_LOOP_INC   = 4,
    MR_HALT       = 5,
};

__declspec(noinline)
int vm_maxrun64_loop_target(uint64_t x) {
    int      idx     = 0;
    int      cur     = 0;
    int      max_run = 0;
    uint64_t xx      = 0;
    int      pc      = MR_LOAD;

    while (1) {
        if (pc == MR_LOAD) {
            xx      = x;
            cur     = 0;
            max_run = 0;
            pc = MR_INIT;
        } else if (pc == MR_INIT) {
            idx = 0;
            pc = MR_LOOP_CHECK;
        } else if (pc == MR_LOOP_CHECK) {
            pc = (idx < 64) ? MR_LOOP_BODY : MR_HALT;
        } else if (pc == MR_LOOP_BODY) {
            if (((xx >> idx) & 1ull) != 0ull) {
                cur = cur + 1;
                if (cur > max_run) {
                    max_run = cur;
                }
            } else {
                cur = 0;
            }
            pc = MR_LOOP_INC;
        } else if (pc == MR_LOOP_INC) {
            idx = idx + 1;
            pc = MR_LOOP_CHECK;
        } else if (pc == MR_HALT) {
            return max_run;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_maxrun64(0xCAFE)=%d vm_maxrun64(max)=%d\n",
           vm_maxrun64_loop_target(0xCAFEull),
           vm_maxrun64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
