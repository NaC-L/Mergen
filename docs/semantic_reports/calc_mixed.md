# calc_mixed - semantic equivalence

- **Verdict:** PASS
- **Cases:** 7/7 passed
- **Source:** `testcases/rewrite_smoke/calc_mixed.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_mixed.ll`
- **Symbol:** `calc_mixed`
- **IR size:** 18 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=150 | 576 | 576 | pass | x>100: (42+150)*3=576 |
| 2 | RCX=101 | 429 | 429 | pass | x>100: (42+101)*3=429 |
| 3 | RCX=0 | 126 | 126 | pass | x<=100: (42-0)*3=126 |
| 4 | RCX=1 | 123 | 123 | pass | x<=100: (42-1)*3=123 |
| 5 | RCX=42 | 0 | 0 | pass | x<=100: (42-42)*3=0 |
| 6 | RCX=50 | 4294967272 | 4294967272 | pass | x<=100: uint32 wrap, zext |
| 7 | RCX=100 | 4294967122 | 4294967122 | pass | x<=100: uint32 wrap, zext |

## Source

```c
/* Mixed symbolic + concrete: branch on input then multiply.
 * Lift target: calc_mixed — symbolic arg, one branch, post-merge math.
 * Expected IR: select on (x > 100), then mul by 3. */
#include <stdio.h>
#include <stdint.h>

__declspec(noinline)
int calc_mixed(int x) {
    uint32_t base = 42u;
    uint32_t ux = (uint32_t)x;
    if (x > 100)
        base += ux;
    else
        base -= ux;
    uint32_t scaled = base * 3u;
    return (int)(int32_t)scaled;
}

int main(void) {
    printf("mixed(150)=%d mixed(50)=%d\n",
           calc_mixed(150), calc_mixed(50));
    return 0;
}
```
