# vm_short_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_short_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_short_array_loop.ll`
- **Symbol:** `vm_short_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_short_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_short_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | seed=0 |
| 2 | RCX=1 | 36 | 36 | 36 | yes | seed=1 |
| 3 | RCX=10 | 360 | 360 | 360 | yes | seed=10 |
| 4 | RCX=100 | 3600 | 3600 | 3600 | yes | seed=100 |
| 5 | RCX=1000 | 36000 | 36000 | 36000 | yes | seed=1000 |
| 6 | RCX=5000 | 48928 | 48928 | 48928 | yes | seed=5000: i16 wrap on i*7,i*8 |
| 7 | RCX=65535 | 4294967260 | 4294967260 | 4294967260 | yes | 0xFFFF: seed=-1 (-36 u32) |
| 8 | RCX=65436 | 4294963696 | 4294963696 | 4294963696 | yes | 0xFF9C: seed=-100 (-3600 u32) |
| 9 | RCX=51966 | 4294937528 | 4294937528 | 4294937528 | yes | 0xCAFE: seed=-13570 (-29768 u32, wraps) |
| 10 | RCX=74565 | 4294964660 | 4294964660 | 4294964660 | yes | 0x12345: seed=0x2345 (-2636 u32) |

## Source

```c
/* PC-state VM that fills a short[8] stack array with signed i16 values
 * and accumulates them via sign-extending loads.
 * Lift target: vm_short_array_loop_target.
 * Goal: cover an i16-element stack array (sext i16 -> i32 at use sites),
 * complementing the i32 / i8 / scalar-i64 / scalar-i16 cases already in
 * the VM corpus.  Symbolic seed keeps mul + sext from being folded.
 */
#include <stdio.h>

enum SaVmPc {
    SA_LOAD       = 0,
    SA_INIT_FILL  = 1,
    SA_FILL_CHECK = 2,
    SA_FILL_BODY  = 3,
    SA_FILL_INC   = 4,
    SA_INIT_SUM   = 5,
    SA_SUM_CHECK  = 6,
    SA_SUM_BODY   = 7,
    SA_SUM_INC    = 8,
    SA_HALT       = 9,
};

__declspec(noinline)
int vm_short_array_loop_target(int x) {
    short buf[8];
    int idx  = 0;
    int sum  = 0;
    short seed = 0;
    int pc   = SA_LOAD;

    while (1) {
        if (pc == SA_LOAD) {
            seed = (short)(x & 0xFFFF);
            pc = SA_INIT_FILL;
        } else if (pc == SA_INIT_FILL) {
            idx = 0;
            pc = SA_FILL_CHECK;
        } else if (pc == SA_FILL_CHECK) {
            pc = (idx < 8) ? SA_FILL_BODY : SA_INIT_SUM;
        } else if (pc == SA_FILL_BODY) {
            buf[idx] = (short)(seed * (short)(idx + 1));
            pc = SA_FILL_INC;
        } else if (pc == SA_FILL_INC) {
            idx = idx + 1;
            pc = SA_FILL_CHECK;
        } else if (pc == SA_INIT_SUM) {
            idx = 0;
            pc = SA_SUM_CHECK;
        } else if (pc == SA_SUM_CHECK) {
            pc = (idx < 8) ? SA_SUM_BODY : SA_HALT;
        } else if (pc == SA_SUM_BODY) {
            sum = sum + (int)buf[idx];
            pc = SA_SUM_INC;
        } else if (pc == SA_SUM_INC) {
            idx = idx + 1;
            pc = SA_SUM_CHECK;
        } else if (pc == SA_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_short_array_loop(0x1388)=%d vm_short_array_loop(0xCAFE)=%d\n",
           vm_short_array_loop_target(0x1388),
           vm_short_array_loop_target(0xCAFE));
    return 0;
}
```
