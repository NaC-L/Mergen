# vm_byte_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byte_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byte_loop.ll`
- **Symbol:** `vm_byte_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byte_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byte_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=0, x=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | limit=0, x=1 |
| 3 | RCX=256 | 5 | 5 | 5 | yes | 0x100: limit=1, state=0 |
| 4 | RCX=768 | 147 | 147 | 147 | yes | 0x300: limit=3, state=0 |
| 5 | RCX=51966 | 44 | 44 | 44 | yes | 0xCAFE: limit=12, state=0xFE |
| 6 | RCX=43981 | 28 | 28 | 28 | yes | 0xABCD: limit=11, state=0xCD |
| 7 | RCX=74565 | 188 | 188 | 188 | yes | 0x12345: limit=3, state=0x45 |
| 8 | RCX=33023 | 255 | 255 | 255 | yes | 0x80FF: limit=0, state=0xFF |
| 9 | RCX=65535 | 82 | 82 | 82 | yes | 0xFFFF: limit=15, state=0xFF |
| 10 | RCX=16962 | 216 | 216 | 216 | yes | 0x4242: limit=2, state=0x42 |

## Source

```c
/* PC-state VM with explicit unsigned char (i8) arithmetic recurrence.
 * Lift target: vm_byte_loop_target.
 * Goal: cover narrower-type (i8) arithmetic inside a VM dispatcher.
 * state = state * 13 + 5 (mod 256), iterated symbolic times.
 * Distinct from existing i32 recurrences and the int64 family.
 */
#include <stdio.h>

enum BvVmPc {
    BV_LOAD       = 0,
    BV_INIT       = 1,
    BV_CHECK      = 2,
    BV_BODY_MUL   = 3,
    BV_BODY_ADD   = 4,
    BV_BODY_DEC   = 5,
    BV_HALT       = 6,
};

__declspec(noinline)
int vm_byte_loop_target(int x) {
    unsigned char state = 0;
    int n = 0;
    int pc = BV_LOAD;

    while (1) {
        if (pc == BV_LOAD) {
            state = (unsigned char)x;
            n = (x >> 8) & 0xF;
            pc = BV_INIT;
        } else if (pc == BV_INIT) {
            pc = BV_CHECK;
        } else if (pc == BV_CHECK) {
            pc = (n > 0) ? BV_BODY_MUL : BV_HALT;
        } else if (pc == BV_BODY_MUL) {
            state = (unsigned char)(state * 13);
            pc = BV_BODY_ADD;
        } else if (pc == BV_BODY_ADD) {
            state = (unsigned char)(state + 5);
            pc = BV_BODY_DEC;
        } else if (pc == BV_BODY_DEC) {
            n = n - 1;
            pc = BV_CHECK;
        } else if (pc == BV_HALT) {
            return (int)state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_byte_loop(0xCAFE)=%d vm_byte_loop(0xFFFF)=%d\n",
           vm_byte_loop_target(0xCAFE),
           vm_byte_loop_target(0xFFFF));
    return 0;
}
```
