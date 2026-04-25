# vm_pcg_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 12/12 passed
- **Source:** `testcases/rewrite_smoke/vm_pcg_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_pcg_loop.ll`
- **Symbol:** `vm_pcg_loop_target`
- **IR size:** 54 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 1 | 1 | pass | n=0, state=1: out=1 |
| 2 | RCX=1 | 1 | 1 | pass | n=0, state=1 |
| 3 | RCX=256 | 21 | 21 | pass | n=1, state=1 |
| 4 | RCX=257 | 21 | 21 | pass | n=1, state=1 (low bit forced) |
| 5 | RCX=512 | 283 | 283 | pass | n=2, state=1 |
| 6 | RCX=768 | 3407 | 3407 | pass | n=3 |
| 7 | RCX=1280 | 63470 | 63470 | pass | n=5 |
| 8 | RCX=3841 | 1993 | 1993 | pass | n=15, state=1 |
| 9 | RCX=4095 | 44770 | 44770 | pass | n=15, state=0xFF |
| 10 | RCX=4660 | 8554 | 8554 | pass | 0x1234 |
| 11 | RCX=39030 | 19508 | 19508 | pass | 0x9876 |
| 12 | RCX=43981 | 21125 | 21125 | pass | 0xABCD |

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
