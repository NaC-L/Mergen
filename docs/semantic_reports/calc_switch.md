# calc_switch - semantic equivalence

- **Verdict:** PASS
- **Cases:** 8/8 passed
- **Source:** `testcases/rewrite_smoke/calc_switch.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_switch.ll`
- **Symbol:** `calc_switch`
- **IR size:** 51 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=1 | 6 | 6 | pass | Monday |
| 2 | RCX=2 | 7 | 7 | pass | Tuesday |
| 3 | RCX=3 | 9 | 9 | pass | Wednesday |
| 4 | RCX=4 | 8 | 8 | pass | Thursday |
| 5 | RCX=5 | 6 | 6 | pass | Friday |
| 6 | RCX=0 | 0 | 0 | pass | default (0) |
| 7 | RCX=6 | 0 | 0 | pass | default (6) |
| 8 | RCX=100 | 0 | 0 | pass | default (100) |

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
