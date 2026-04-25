# calc_grade - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/calc_grade.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_grade.ll`
- **Symbol:** `calc_grade`
- **IR size:** 30 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=95 | 4 | 4 | pass | >=90 |
| 2 | RCX=90 | 4 | 4 | pass | ==90 boundary |
| 3 | RCX=89 | 3 | 3 | pass | 80..89 |
| 4 | RCX=80 | 3 | 3 | pass | ==80 boundary |
| 5 | RCX=79 | 2 | 2 | pass | 70..79 |
| 6 | RCX=70 | 2 | 2 | pass | ==70 boundary |
| 7 | RCX=69 | 1 | 1 | pass | 60..69 |
| 8 | RCX=60 | 1 | 1 | pass | ==60 boundary |
| 9 | RCX=59 | 0 | 0 | pass | <60 |
| 10 | RCX=0 | 0 | 0 | pass | <60 zero |
| 11 | RCX=100 | 4 | 4 | pass | >=90 well above |

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
