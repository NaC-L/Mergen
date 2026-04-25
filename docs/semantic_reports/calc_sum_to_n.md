# calc_sum_to_n - semantic equivalence

- **Verdict:** PASS
- **Cases:** 6/6 passed
- **Source:** `testcases/rewrite_smoke/calc_sum_to_n.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_sum_to_n.ll`
- **Symbol:** `calc_sum_to_n`
- **IR size:** 44 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 0 | 0 | pass | n=0 |
| 2 | RCX=1 | 0 | 0 | pass | n=1 |
| 3 | RCX=5 | 10 | 10 | pass | 0+1+2+3+4 |
| 4 | RCX=10 | 45 | 45 | pass | 0..9 |
| 5 | RCX=32 | 496 | 496 | pass | 0..31 |
| 6 | RCX=100 | 496 | 496 | pass | clamped to 32 |

## Source

```c
/* Symbolic trip-count counted loop.
 * Lift target: calc_sum_to_n — symbolic loop bound with a clamp.
 * Goal: preserve real loop structure (phi/backedge/compare), not constant-fold.
 */
#include <stdio.h>

__declspec(noinline)
int calc_sum_to_n(int n) {
    if (n > 32)
        n = 32;

    int sum = 0;
    for (int i = 0; i < n; i++)
        sum += i;

    return sum;
}

int main(void) {
    printf("sum_to_n(5)=%d sum_to_n(10)=%d\n",
           calc_sum_to_n(5), calc_sum_to_n(10));
    return 0;
}
```
