# vm_imported_rotl_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_imported_rotl_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_rotl_loop.ll`
- **Symbol:** `vm_imported_rotl_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_imported_rotl_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_imported_rotl_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, x=0 |
| 2 | RCX=1 | 1352 | 1352 | 1352 | yes | limit=2, x=1 |
| 3 | RCX=7 | 1045112 | 1045112 | 1045112 | yes | limit=8, x=7 |
| 4 | RCX=255 | 981688 | 981688 | 981688 | yes | 0xFF: limit=8 |
| 5 | RCX=256 | 2048 | 2048 | 2048 | yes | 0x100: limit=1 |
| 6 | RCX=51966 | 52820320 | 52820320 | 52820320 | yes | 0xCAFE: limit=7 |
| 7 | RCX=43981 | 22020552 | 22020552 | 22020552 | yes | 0xABCD: limit=6 |
| 8 | RCX=74565 | 37530632 | 37530632 | 37530632 | yes | 0x12345: limit=6 |
| 9 | RCX=-1 | 4293921448 | 4293921448 | 4293921448 | yes | all F |
| 10 | RCX=-559038737 | 2021747745 | 2021747745 | 2021747745 | yes | 0xDEADBEEF |

## Source

```c
/* PC-state VM whose body calls _rotl (lowered by clang to @llvm.fshl.i32)
 * with both value and rotation count varying per iteration.
 * Lift target: vm_imported_rotl_loop_target.
 * Goal: cover a sixth recognized-intrinsic shape - funnel-shift rotate.
 * The rotate amount is symbolic and depends on the loop index, so each
 * call has a distinct pre/post bit pattern.
 */
#include <stdio.h>
#include <stdlib.h>

enum RlVmPc {
    RL_LOAD       = 0,
    RL_INIT       = 1,
    RL_CHECK      = 2,
    RL_BODY_XOR   = 3,
    RL_BODY_AMOUNT= 4,
    RL_BODY_CALL  = 5,
    RL_BODY_ADD   = 6,
    RL_BODY_INC   = 7,
    RL_HALT       = 8,
};

__declspec(noinline)
int vm_imported_rotl_loop_target(int x) {
    unsigned limit = 0;
    unsigned idx   = 0;
    unsigned sum   = 0;
    unsigned v     = 0;
    unsigned amt   = 0;
    unsigned rot   = 0;
    int pc         = RL_LOAD;

    while (1) {
        if (pc == RL_LOAD) {
            limit = ((unsigned)x & 7) + 1;
            sum = 0;
            pc = RL_INIT;
        } else if (pc == RL_INIT) {
            idx = 0;
            pc = RL_CHECK;
        } else if (pc == RL_CHECK) {
            pc = (idx < limit) ? RL_BODY_XOR : RL_HALT;
        } else if (pc == RL_BODY_XOR) {
            v = (unsigned)x ^ (idx * 0x55);
            pc = RL_BODY_AMOUNT;
        } else if (pc == RL_BODY_AMOUNT) {
            amt = (idx + 3) & 31;
            pc = RL_BODY_CALL;
        } else if (pc == RL_BODY_CALL) {
            rot = _rotl(v, (int)amt);
            pc = RL_BODY_ADD;
        } else if (pc == RL_BODY_ADD) {
            sum = sum + rot;
            pc = RL_BODY_INC;
        } else if (pc == RL_BODY_INC) {
            idx = idx + 1;
            pc = RL_CHECK;
        } else if (pc == RL_HALT) {
            return (int)sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_rotl_loop(0xCAFE)=%u vm_imported_rotl_loop(0xDEADBEEF)=%u\n",
           (unsigned)vm_imported_rotl_loop_target(0xCAFE),
           (unsigned)vm_imported_rotl_loop_target((int)0xDEADBEEFu));
    return 0;
}
```
