# vm_horner_signed_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_horner_signed_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_horner_signed_loop.ll`
- **Symbol:** `vm_horner_signed_loop_target`
- **IR size:** 25 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 4294967294 | 4294967294 | pass | t=1: -2 unsigned |
| 2 | RCX=1 | 2 | 2 | pass | t=2: 2 |
| 3 | RCX=2 | 14 | 14 | pass | t=3: 14 |
| 4 | RCX=3 | 40 | 40 | pass | t=4: 40 |
| 5 | RCX=4 | 86 | 86 | pass | t=5: 86 |
| 6 | RCX=5 | 158 | 158 | pass | t=6: 158 |
| 7 | RCX=6 | 262 | 262 | pass | t=7: 262 |
| 8 | RCX=7 | 404 | 404 | pass | t=8: 404 |
| 9 | RCX=8 | 4294967294 | 4294967294 | pass | t=1 again (mask drops bit 3) |
| 10 | RCX=15 | 404 | 404 | pass | t=8 again after mask |

## Source

```c
/* PC-state VM evaluating a polynomial with signed coefficients via Horner's
 * method.
 * Lift target: vm_horner_signed_loop_target.
 * Goal: cover signed multiply-and-add inside a loop where the coefficient
 * array contains negative values.  Distinct from vm_polynomial_loop (all
 * positive coefficients): tests sign extension of small constants stored
 * to a stack array and consumed by mul.  p(t) = t^3 - 2t^2 + 3t - 4.
 */
#include <stdio.h>

enum HsVmPc {
    HS_LOAD       = 0,
    HS_INIT       = 1,
    HS_INIT_COEF  = 2,
    HS_CHECK      = 3,
    HS_BODY_LOAD  = 4,
    HS_BODY_MUL   = 5,
    HS_BODY_ADD   = 6,
    HS_BODY_INC   = 7,
    HS_HALT       = 8,
};

__declspec(noinline)
int vm_horner_signed_loop_target(int x) {
    int coef[4];
    int t      = 0;
    int i      = 0;
    int result = 0;
    int c      = 0;
    int prod   = 0;
    int pc     = HS_LOAD;

    while (1) {
        if (pc == HS_LOAD) {
            t = (x & 7) + 1;
            i = 0;
            result = 0;
            pc = HS_INIT_COEF;
        } else if (pc == HS_INIT_COEF) {
            coef[0] = 1;
            coef[1] = -2;
            coef[2] = 3;
            coef[3] = -4;
            pc = HS_CHECK;
        } else if (pc == HS_CHECK) {
            pc = (i < 4) ? HS_BODY_LOAD : HS_HALT;
        } else if (pc == HS_BODY_LOAD) {
            c = coef[i];
            pc = HS_BODY_MUL;
        } else if (pc == HS_BODY_MUL) {
            prod = result * t;
            pc = HS_BODY_ADD;
        } else if (pc == HS_BODY_ADD) {
            result = prod + c;
            pc = HS_BODY_INC;
        } else if (pc == HS_BODY_INC) {
            i = i + 1;
            pc = HS_CHECK;
        } else if (pc == HS_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_horner_signed_loop(0)=%d vm_horner_signed_loop(7)=%d\n",
           vm_horner_signed_loop_target(0), vm_horner_signed_loop_target(7));
    return 0;
}
```
