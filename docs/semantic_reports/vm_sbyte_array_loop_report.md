# vm_sbyte_array_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_sbyte_array_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_sbyte_array_loop.ll`
- **Symbol:** `vm_sbyte_array_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_sbyte_array_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_sbyte_array_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | seed=0 |
| 2 | RCX=1 | 56 | 56 | 56 | yes | seed=1: arithmetic seq sum |
| 3 | RCX=2 | 112 | 112 | 112 | yes | seed=2 |
| 4 | RCX=5 | 280 | 280 | 280 | yes | seed=5 |
| 5 | RCX=10 | 560 | 560 | 560 | yes | seed=10 |
| 6 | RCX=20 | 4294967136 | 4294967136 | 4294967136 | yes | seed=20: i8 wrap on high indices (-160 u32) |
| 7 | RCX=127 | 456 | 456 | 456 | yes | seed=0x7F: max positive |
| 8 | RCX=128 | 4294966272 | 4294966272 | 4294966272 | yes | seed=-128 (-1024 u32) |
| 9 | RCX=255 | 4294967240 | 4294967240 | 4294967240 | yes | seed=-1 (-56 u32) |
| 10 | RCX=51966 | 4294967184 | 4294967184 | 4294967184 | yes | 0xCAFE: low byte 0xFE -> seed=-2 (-112 u32) |

## Source

```c
/* PC-state VM that fills a signed-char[16] stack array and accumulates
 * via sign-extending byte loads.
 * Lift target: vm_sbyte_array_loop_target.
 * Goal: cover an i8-element stack array with SIGNED element type
 * (sext i8 -> i32 at use sites), distinct from vm_byte_buffer_loop which
 * uses unsigned-char[] (zext i8).  Mirrors the i16 sext/zext pair.
 */
#include <stdio.h>

enum SbVmPc {
    SB_LOAD       = 0,
    SB_INIT_FILL  = 1,
    SB_FILL_CHECK = 2,
    SB_FILL_BODY  = 3,
    SB_FILL_INC   = 4,
    SB_INIT_SUM   = 5,
    SB_SUM_CHECK  = 6,
    SB_SUM_BODY   = 7,
    SB_SUM_INC    = 8,
    SB_HALT       = 9,
};

__declspec(noinline)
int vm_sbyte_array_loop_target(int x) {
    signed char buf[16];
    int idx  = 0;
    int sum  = 0;
    signed char seed = 0;
    int pc   = SB_LOAD;

    while (1) {
        if (pc == SB_LOAD) {
            seed = (signed char)(x & 0xFF);
            pc = SB_INIT_FILL;
        } else if (pc == SB_INIT_FILL) {
            idx = 0;
            pc = SB_FILL_CHECK;
        } else if (pc == SB_FILL_CHECK) {
            pc = (idx < 16) ? SB_FILL_BODY : SB_INIT_SUM;
        } else if (pc == SB_FILL_BODY) {
            buf[idx] = (signed char)((int)seed * (idx - 4));
            pc = SB_FILL_INC;
        } else if (pc == SB_FILL_INC) {
            idx = idx + 1;
            pc = SB_FILL_CHECK;
        } else if (pc == SB_INIT_SUM) {
            idx = 0;
            pc = SB_SUM_CHECK;
        } else if (pc == SB_SUM_CHECK) {
            pc = (idx < 16) ? SB_SUM_BODY : SB_HALT;
        } else if (pc == SB_SUM_BODY) {
            sum = sum + (int)buf[idx];
            pc = SB_SUM_INC;
        } else if (pc == SB_SUM_INC) {
            idx = idx + 1;
            pc = SB_SUM_CHECK;
        } else if (pc == SB_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_sbyte_array_loop(10)=%d vm_sbyte_array_loop(0xFF)=%d\n",
           vm_sbyte_array_loop_target(10),
           vm_sbyte_array_loop_target(0xFF));
    return 0;
}
```
