# calc_fib - semantic equivalence

- **Verdict:** PASS
- **Cases:** 1/1 passed
- **Source:** `testcases/rewrite_smoke/calc_fib.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_fib.ll`
- **Symbol:** `calc_fib`
- **IR size:** 11 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | _(none)_ | 13 | 13 | pass | constant: fib(7) |

## Source

```c
/* Iterative Fibonacci with constant bound.
 * Lift target: calc_fib — concrete loop (7 iterations), stack variables.
 * fib(7) = 13.  Concolic engine should unroll; LLVM folds to constant.
 * This is the first test of real compiler-generated /Od loop code. */
#include <stdio.h>

__declspec(noinline)
int calc_fib(void) {
    int a = 0, b = 1;
    for (int i = 0; i < 7; i++) {
        int t = a + b;
        a = b;
        b = t;
    }
    return a;
}

int main(void) {
    printf("fib(7)=%d\n", calc_fib());
    return 0;
}
```
