# calc_grade - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/calc_grade.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_grade.ll`
- **Symbol:** `calc_grade`
- **Native driver:** `rewrite-regression-work/eq/calc_grade_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `calc_grade` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=95 | 4 | 4 | 4 | yes | >=90 |
| 2 | RCX=90 | 4 | 4 | 4 | yes | ==90 boundary |
| 3 | RCX=89 | 3 | 3 | 3 | yes | 80..89 |
| 4 | RCX=80 | 3 | 3 | 3 | yes | ==80 boundary |
| 5 | RCX=79 | 2 | 2 | 2 | yes | 70..79 |
| 6 | RCX=70 | 2 | 2 | 2 | yes | ==70 boundary |
| 7 | RCX=69 | 1 | 1 | 1 | yes | 60..69 |
| 8 | RCX=60 | 1 | 1 | 1 | yes | ==60 boundary |
| 9 | RCX=59 | 0 | 0 | 0 | yes | <60 |
| 10 | RCX=0 | 0 | 0 | 0 | yes | <60 zero |
| 11 | RCX=100 | 4 | 4 | 4 | yes | >=90 well above |

## Source

```c
/* Grade calculator: cascading if/else on symbolic input (ECX).
 * Lift target: calc_grade — no loops, pure branching.
 * Expected IR: chain of icmp + select on the symbolic argument. */
#include <stdio.h>

__declspec(noinline)
int calc_grade(int score) {
    if (score >= 90) return 4;   /* A */
    if (score >= 80) return 3;   /* B */
    if (score >= 70) return 2;   /* C */
    if (score >= 60) return 1;   /* D */
    return 0;                    /* F */
}

int main(void) {
    printf("grade(95)=%d grade(82)=%d grade(55)=%d\n",
           calc_grade(95), calc_grade(82), calc_grade(55));
    return 0;
}
```
