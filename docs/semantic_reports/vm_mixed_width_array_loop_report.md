# vm_mixed_width_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_mixed_width_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_mixed_width_array_loop.ll`
- **Symbol:** `vm_mixed_width_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_mixed_width_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_mixed_width_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 12 | 12 | 12 | yes | seed=0: only constant adds |
| 2 | RCX=1 | 30 | 30 | 30 | yes | seed=1 |
| 3 | RCX=5 | 102 | 102 | 102 | yes | seed=5 |
| 4 | RCX=10 | 192 | 192 | 192 | yes | seed=10 |
| 5 | RCX=100 | 1812 | 1812 | 1812 | yes | seed=100 |
| 6 | RCX=1000 | 13916 | 13916 | 13916 | yes | seed=1000 |
| 7 | RCX=10000 | 140076 | 140076 | 140076 | yes | seed=10000: i8 wraps in c[] |
| 8 | RCX=32768 | 196620 | 196620 | 196620 | yes | seed=0x8000: i16 wraps to negative in b[] |
| 9 | RCX=40000 | 298124 | 298124 | 298124 | yes | seed=40000: both b[] and c[] wrap |
| 10 | RCX=2147483647 | 4294967290 | 4294967290 | 4294967290 | yes | INT_MAX |
| 11 | RCX=4294967295 | 4294967290 | 4294967290 | 4294967290 | yes | -1 u32 |
| 12 | RCX=3405691582 | 3992073576 | 3992073576 | 3992073576 | yes | 0xCAFEBABE |

## Source

```c
/* PC-state VM that allocates THREE stack arrays of different element
 * widths in the same frame and sums across them.
 * Lift target: vm_mixed_width_array_loop_target.
 * Goal: stress heterogeneous stack-frame layout (int[4] + short[4] +
 * signed char[4]).  All three are filled in one fill loop and then
 * accumulated in a separate sum loop, exercising sext i16 + sext i8 +
 * native i32 loads from the same stack region.
 */
#include <stdio.h>

enum MwVmPc {
    MW_LOAD       = 0,
    MW_INIT_FILL  = 1,
    MW_FILL_CHECK = 2,
    MW_FILL_BODY  = 3,
    MW_FILL_INC   = 4,
    MW_INIT_SUM   = 5,
    MW_SUM_CHECK  = 6,
    MW_SUM_BODY   = 7,
    MW_SUM_INC    = 8,
    MW_HALT       = 9,
};

__declspec(noinline)
int vm_mixed_width_array_loop_target(int x) {
    int          a[4];
    short        b[4];
    signed char  c[4];
    int idx  = 0;
    int sum  = 0;
    int seed = 0;
    int pc   = MW_LOAD;

    while (1) {
        if (pc == MW_LOAD) {
            seed = x;
            pc = MW_INIT_FILL;
        } else if (pc == MW_INIT_FILL) {
            idx = 0;
            pc = MW_FILL_CHECK;
        } else if (pc == MW_FILL_CHECK) {
            pc = (idx < 4) ? MW_FILL_BODY : MW_INIT_SUM;
        } else if (pc == MW_FILL_BODY) {
            a[idx] = seed * (idx + 1);
            b[idx] = (short)(seed + idx * 7);
            c[idx] = (signed char)(seed - idx * 5);
            pc = MW_FILL_INC;
        } else if (pc == MW_FILL_INC) {
            idx = idx + 1;
            pc = MW_FILL_CHECK;
        } else if (pc == MW_INIT_SUM) {
            idx = 0;
            pc = MW_SUM_CHECK;
        } else if (pc == MW_SUM_CHECK) {
            pc = (idx < 4) ? MW_SUM_BODY : MW_HALT;
        } else if (pc == MW_SUM_BODY) {
            sum = sum + a[idx] + (int)b[idx] + (int)c[idx];
            pc = MW_SUM_INC;
        } else if (pc == MW_SUM_INC) {
            idx = idx + 1;
            pc = MW_SUM_CHECK;
        } else if (pc == MW_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_mixed_width(10000)=%d vm_mixed_width(40000)=%d\n",
           vm_mixed_width_array_loop_target(10000),
           vm_mixed_width_array_loop_target(40000));
    return 0;
}
```
