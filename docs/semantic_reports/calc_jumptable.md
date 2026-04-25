# calc_jumptable - semantic equivalence

- **Verdict:** PASS
- **Cases:** 12/12 passed
- **Source:** `testcases/rewrite_smoke/calc_jumptable.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_jumptable.ll`
- **Symbol:** `calc_jumptable`
- **IR size:** 66 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=-1 | 4294967295 | 4294967295 | pass | default (negative) |
| 2 | RCX=0 | 1 | 1 | pass | 2^0 |
| 3 | RCX=1 | 2 | 2 | pass | 2^1 |
| 4 | RCX=2 | 4 | 4 | pass | 2^2 |
| 5 | RCX=3 | 8 | 8 | pass | 2^3 |
| 6 | RCX=4 | 16 | 16 | pass | 2^4 |
| 7 | RCX=5 | 32 | 32 | pass | 2^5 |
| 8 | RCX=6 | 64 | 64 | pass | 2^6 |
| 9 | RCX=7 | 128 | 128 | pass | 2^7 |
| 10 | RCX=8 | 256 | 256 | pass | 2^8 |
| 11 | RCX=9 | 512 | 512 | pass | 2^9 |
| 12 | RCX=10 | 4294967295 | 4294967295 | pass | default (above range) |

## Source

```c
/* Jump table test: MSVC /O2 should emit a real jump table for 7+ dense cases.
 * Lift target: calc_jumptable
 * Expected IR: switch (or equivalent multi-target branch) on symbolic input.
 *
 * NOTE: Must be compiled with /O2 (not /Od) to generate jmp [table + reg*8].
 * /Od generates compare chains which the lifter already handles. */

#include <stdio.h>

__declspec(noinline)
int calc_jumptable(int op) {
    switch (op) {
    case 0: return 1;
    case 1: return 2;
    case 2: return 4;
    case 3: return 8;
    case 4: return 16;
    case 5: return 32;
    case 6: return 64;
    case 7: return 128;
    case 8: return 256;
    case 9: return 512;
    default: return -1;
    }
}

int main(void) {
    printf("jt(0)=%d jt(5)=%d jt(9)=%d jt(99)=%d\n",
           calc_jumptable(0), calc_jumptable(5),
           calc_jumptable(9), calc_jumptable(99));
    return 0;
}
```
