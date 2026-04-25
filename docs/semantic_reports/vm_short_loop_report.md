# vm_short_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_short_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_short_loop.ll`
- **Symbol:** `vm_short_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_short_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_short_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=0, state=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | limit=0, state=1 |
| 3 | RCX=65536 | 0 | 0 | 0 | yes | 0x10000: limit=1, state=0 |
| 4 | RCX=131073 | 52 | 52 | 52 | yes | 0x20001: limit=2, state=1 |
| 5 | RCX=196608 | 27 | 27 | 27 | yes | 0x30000: limit=3, state=0 |
| 6 | RCX=458752 | 3089 | 3089 | 3089 | yes | 0x70000: limit=7, state=0 |
| 7 | RCX=51966 | 4294953726 | 4294953726 | 4294953726 | yes | 0xCAFE: state -13570 zext to u32 |
| 8 | RCX=16829182 | 4294953726 | 4294953726 | 4294953726 | yes | 0x100CAFE: limit=0 |
| 9 | RCX=74565 | 4294964963 | 4294964963 | 4294964963 | yes | 0x12345: state -2333 zext |
| 10 | RCX=-2147483648 | 0 | 0 | 0 | yes | 0x80000000: limit=0, state=0 |

## Source

```c
/* PC-state VM with i16 (short) arithmetic recurrence.
 * Lift target: vm_short_loop_target.
 * Goal: cover i16 arithmetic inside a VM dispatcher; the result is
 * sign-extended back to int at return.  Distinct from vm_byte_loop (i8)
 * and the i32 / i64 family.
 */
#include <stdio.h>

enum SvVmPc {
    SV_LOAD       = 0,
    SV_INIT       = 1,
    SV_CHECK      = 2,
    SV_BODY_MUL   = 3,
    SV_BODY_ADD   = 4,
    SV_BODY_INC   = 5,
    SV_HALT       = 6,
};

__declspec(noinline)
int vm_short_loop_target(int x) {
    short state = 0;
    int n   = 0;
    int idx = 0;
    int pc  = SV_LOAD;

    while (1) {
        if (pc == SV_LOAD) {
            state = (short)(x & 0xFFFF);
            n = (x >> 16) & 7;
            pc = SV_INIT;
        } else if (pc == SV_INIT) {
            idx = 0;
            pc = SV_CHECK;
        } else if (pc == SV_CHECK) {
            pc = (idx < n) ? SV_BODY_MUL : SV_HALT;
        } else if (pc == SV_BODY_MUL) {
            state = (short)(state * 7);
            pc = SV_BODY_ADD;
        } else if (pc == SV_BODY_ADD) {
            state = (short)(state + idx * 3);
            pc = SV_BODY_INC;
        } else if (pc == SV_BODY_INC) {
            idx = idx + 1;
            pc = SV_CHECK;
        } else if (pc == SV_HALT) {
            return (int)state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_short_loop(0xCAFE)=%d vm_short_loop(0x70000)=%d\n",
           vm_short_loop_target(0xCAFE),
           vm_short_loop_target(0x70000));
    return 0;
}
```
