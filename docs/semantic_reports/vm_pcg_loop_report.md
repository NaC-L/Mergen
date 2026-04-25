# vm_pcg_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_pcg_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_pcg_loop.ll`
- **Symbol:** `vm_pcg_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_pcg_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_pcg_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | n=0, state=1: out=1 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | n=0, state=1 |
| 3 | RCX=256 | 21 | 21 | 21 | yes | n=1, state=1 |
| 4 | RCX=257 | 21 | 21 | 21 | yes | n=1, state=1 (low bit forced) |
| 5 | RCX=512 | 283 | 283 | 283 | yes | n=2, state=1 |
| 6 | RCX=768 | 3407 | 3407 | 3407 | yes | n=3 |
| 7 | RCX=1280 | 63470 | 63470 | 63470 | yes | n=5 |
| 8 | RCX=3841 | 1993 | 1993 | 1993 | yes | n=15, state=1 |
| 9 | RCX=4095 | 44770 | 44770 | 44770 | yes | n=15, state=0xFF |
| 10 | RCX=4660 | 8554 | 8554 | 8554 | yes | 0x1234 |
| 11 | RCX=39030 | 19508 | 19508 | 19508 | yes | 0x9876 |
| 12 | RCX=43981 | 21125 | 21125 | 21125 | yes | 0xABCD |

## Source

```c
/* PC-state VM running a PCG-style RNG: LCG state advance plus XOR-shift
 * output mixing per iteration.
 * Lift target: vm_pcg_loop_target.
 * Goal: cover a loop body that combines LCG-style multiply-add with
 * XOR-shift mixing on the same state, producing a non-trivial pseudo-
 * random output.  Distinct from vm_lcg_loop (LCG only) and vm_lfsr_loop
 * (shift+conditional-XOR only).
 */
#include <stdio.h>

enum PgVmPc {
    PG_LOAD       = 0,
    PG_INIT       = 1,
    PG_CHECK      = 2,
    PG_BODY_LCG   = 3,
    PG_BODY_MIX   = 4,
    PG_BODY_DEC   = 5,
    PG_HALT       = 6,
};

__declspec(noinline)
int vm_pcg_loop_target(int x) {
    int state = 0;
    int n     = 0;
    int out   = 0;
    int tmp   = 0;
    int pc    = PG_LOAD;

    while (1) {
        if (pc == PG_LOAD) {
            state = (x & 0xFF) | 1;
            n = (x >> 8) & 0xF;
            out = state;
            pc = PG_INIT;
        } else if (pc == PG_INIT) {
            pc = PG_CHECK;
        } else if (pc == PG_CHECK) {
            pc = (n > 0) ? PG_BODY_LCG : PG_HALT;
        } else if (pc == PG_BODY_LCG) {
            state = (state * 13 + 7) & 0xFFFF;
            pc = PG_BODY_MIX;
        } else if (pc == PG_BODY_MIX) {
            tmp = (int)((unsigned)state >> 4);
            out = (state ^ tmp) & 0xFFFF;
            pc = PG_BODY_DEC;
        } else if (pc == PG_BODY_DEC) {
            n = n - 1;
            pc = PG_CHECK;
        } else if (pc == PG_HALT) {
            return out;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_pcg_loop(0xFFF)=%d vm_pcg_loop(0xABCD)=%d\n",
           vm_pcg_loop_target(0xFFF), vm_pcg_loop_target(0xABCD));
    return 0;
}
```
