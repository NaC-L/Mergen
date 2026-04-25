# calc_cout - semantic equivalence

- **Verdict:** PASS
- **Cases:** 4/4 passed
- **Source:** `testcases/rewrite_smoke/calc_cout.cpp`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_cout.ll`
- **Symbol:** `?calc_cout@@YAHH@Z`
- **IR size:** 13 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=10 | 37 | 37 | pass | 10*3+7 |
| 2 | RCX=0 | 7 | 7 | pass | 0*3+7 |
| 3 | RCX=100 | 307 | 307 | pass | 100*3+7 |
| 4 | RCX=1 | 10 | 10 | pass | 1*3+7 |

## Source

```cpp
/* Test: function with cout call.
 * Lift target: calc_cout — external call handling.
 * The computation is pure, but it calls cout before returning. */
#include <iostream>

__declspec(noinline)
int calc_cout(int x) {
    int result = x * 3 + 7;
    std::cout << result;
    return result;
}

int main() {
    int r = calc_cout(10);
    return r;
}
```
