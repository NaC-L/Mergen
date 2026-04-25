# calc_switch - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 8/8 equivalent
- **Source:** `testcases/rewrite_smoke/calc_switch.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_switch.ll`
- **Symbol:** `calc_switch`
- **Native driver:** `rewrite-regression-work/eq/calc_switch_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `calc_switch` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=1 | 6 | 6 | 6 | yes | Monday |
| 2 | RCX=2 | 7 | 7 | 7 | yes | Tuesday |
| 3 | RCX=3 | 9 | 9 | 9 | yes | Wednesday |
| 4 | RCX=4 | 8 | 8 | 8 | yes | Thursday |
| 5 | RCX=5 | 6 | 6 | 6 | yes | Friday |
| 6 | RCX=0 | 0 | 0 | 0 | yes | default (0) |
| 7 | RCX=6 | 0 | 0 | 0 | yes | default (6) |
| 8 | RCX=100 | 0 | 0 | 0 | yes | default (100) |

## Source

```c
/* Day-of-week name length: switch with 5 cases + default.
 * Lift target: calc_switch — multi-target branch resolution.
 * Expected IR: switch on symbolic input, resolving all case targets. */
#include <stdio.h>

__declspec(noinline)
int calc_switch(int day) {
    switch (day) {
    case 1: return 6;  /* Monday */
    case 2: return 7;  /* Tuesday */
    case 3: return 9;  /* Wednesday */
    case 4: return 8;  /* Thursday */
    case 5: return 6;  /* Friday */
    default: return 0; /* invalid */
    }
}

int main(void) {
    printf("switch(1)=%d switch(3)=%d switch(5)=%d switch(9)=%d\n",
           calc_switch(1), calc_switch(3), calc_switch(5), calc_switch(9));
    return 0;
}
```
