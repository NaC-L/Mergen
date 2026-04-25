# vm_byte_buffer_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byte_buffer_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byte_buffer_loop.ll`
- **Symbol:** `vm_byte_buffer_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byte_buffer_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byte_buffer_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 840 | 840 | 840 | yes | seed=0 |
| 2 | RCX=1 | 856 | 856 | 856 | yes | seed=1 |
| 3 | RCX=5 | 920 | 920 | 920 | yes | seed=5 |
| 4 | RCX=7 | 952 | 952 | 952 | yes | seed=7 |
| 5 | RCX=16 | 1096 | 1096 | 1096 | yes | 0x10 |
| 6 | RCX=85 | 2200 | 2200 | 2200 | yes | 0x55 |
| 7 | RCX=128 | 2888 | 2888 | 2888 | yes | 0x80 |
| 8 | RCX=255 | 1080 | 1080 | 1080 | yes | 0xFF: wrap-modulated |
| 9 | RCX=51966 | 1064 | 1064 | 1064 | yes | 0xCAFE: seed=0xFE |
| 10 | RCX=74565 | 1944 | 1944 | 1944 | yes | 0x12345: seed=0x45 |

## Source

```c
/* PC-state VM that fills a 16-byte stack buffer (uint8_t buf[16]) and
 * sums it in a separate pass.
 * Lift target: vm_byte_buffer_loop_target.
 * Goal: cover an i8-element stack array (distinct from int[] arrays and
 * from the scalar-i8 vm_byte_loop case).  Two PC-state passes (fill +
 * accumulate); both have a fixed 16-trip bound and may be unrolled.
 */
#include <stdio.h>

enum BbVmPc {
    BB_LOAD       = 0,
    BB_INIT_FILL  = 1,
    BB_FILL_CHECK = 2,
    BB_FILL_BODY  = 3,
    BB_FILL_INC   = 4,
    BB_INIT_SUM   = 5,
    BB_SUM_CHECK  = 6,
    BB_SUM_BODY   = 7,
    BB_SUM_INC    = 8,
    BB_HALT       = 9,
};

__declspec(noinline)
int vm_byte_buffer_loop_target(int x) {
    unsigned char buf[16];
    int idx  = 0;
    int sum  = 0;
    int seed = 0;
    int pc   = BB_LOAD;

    while (1) {
        if (pc == BB_LOAD) {
            seed = x & 0xFF;
            pc = BB_INIT_FILL;
        } else if (pc == BB_INIT_FILL) {
            idx = 0;
            pc = BB_FILL_CHECK;
        } else if (pc == BB_FILL_CHECK) {
            pc = (idx < 16) ? BB_FILL_BODY : BB_INIT_SUM;
        } else if (pc == BB_FILL_BODY) {
            buf[idx] = (unsigned char)((idx * 7 + seed) & 0xFF);
            pc = BB_FILL_INC;
        } else if (pc == BB_FILL_INC) {
            idx = idx + 1;
            pc = BB_FILL_CHECK;
        } else if (pc == BB_INIT_SUM) {
            idx = 0;
            pc = BB_SUM_CHECK;
        } else if (pc == BB_SUM_CHECK) {
            pc = (idx < 16) ? BB_SUM_BODY : BB_HALT;
        } else if (pc == BB_SUM_BODY) {
            sum = sum + (int)buf[idx];
            pc = BB_SUM_INC;
        } else if (pc == BB_SUM_INC) {
            idx = idx + 1;
            pc = BB_SUM_CHECK;
        } else if (pc == BB_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_byte_buffer_loop(0x55)=%d vm_byte_buffer_loop(0xFF)=%d\n",
           vm_byte_buffer_loop_target(0x55),
           vm_byte_buffer_loop_target(0xFF));
    return 0;
}
```
