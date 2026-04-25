# vm_palindrome_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 14/14 passed
- **Source:** `testcases/rewrite_smoke/vm_palindrome_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_palindrome_loop.ll`
- **Symbol:** `vm_palindrome_loop_target`
- **IR size:** 92 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 1 | 1 | pass | 0x00 palindrome |
| 2 | RCX=1 | 0 | 0 | pass | 0x01 not palindrome |
| 3 | RCX=24 | 1 | 1 | pass | 0x18 palindrome (00011000) |
| 4 | RCX=36 | 1 | 1 | pass | 0x24 palindrome (00100100) |
| 5 | RCX=66 | 1 | 1 | pass | 0x42 palindrome (01000010) |
| 6 | RCX=85 | 0 | 0 | pass | 0x55 not palindrome |
| 7 | RCX=102 | 1 | 1 | pass | 0x66 palindrome (01100110) |
| 8 | RCX=129 | 1 | 1 | pass | 0x81 palindrome (10000001) |
| 9 | RCX=153 | 1 | 1 | pass | 0x99 palindrome (10011001) |
| 10 | RCX=195 | 1 | 1 | pass | 0xC3 palindrome (11000011) |
| 11 | RCX=231 | 1 | 1 | pass | 0xE7 palindrome (11100111) |
| 12 | RCX=255 | 1 | 1 | pass | 0xFF palindrome |
| 13 | RCX=256 | 1 | 1 | pass | 0x00 again (mask drops bit 8) |
| 14 | RCX=394 | 0 | 0 | pass | 0x18A: low byte 0x8A not palindrome |

## Source

```c
/* PC-state VM that checks whether the low 8 bits of x form a bit-palindrome.
 * Lift target: vm_palindrome_loop_target.
 * Goal: cover an early-exit loop where each iteration compares two bits
 * extracted from different positions and aborts as soon as they differ.
 * Distinct from vm_search_loop (compares against a fixed table) and
 * vm_bittransitions_loop (counts mismatches without exiting).
 */
#include <stdio.h>

enum PalVmPc {
    PA_LOAD       = 0,
    PA_INIT       = 1,
    PA_CHECK      = 2,
    PA_BODY_LOAD  = 3,
    PA_BODY_TEST  = 4,
    PA_BODY_INC   = 5,
    PA_HALT_NO    = 6,
    PA_HALT_YES   = 7,
};

__declspec(noinline)
int vm_palindrome_loop_target(int x) {
    int v   = 0;
    int idx = 0;
    int bi  = 0;
    int bj  = 0;
    int pc  = PA_LOAD;

    while (1) {
        if (pc == PA_LOAD) {
            v = x & 0xFF;
            idx = 0;
            pc = PA_INIT;
        } else if (pc == PA_INIT) {
            pc = PA_CHECK;
        } else if (pc == PA_CHECK) {
            pc = (idx < 4) ? PA_BODY_LOAD : PA_HALT_YES;
        } else if (pc == PA_BODY_LOAD) {
            bi = (v >> idx) & 1;
            bj = (v >> (7 - idx)) & 1;
            pc = PA_BODY_TEST;
        } else if (pc == PA_BODY_TEST) {
            pc = (bi == bj) ? PA_BODY_INC : PA_HALT_NO;
        } else if (pc == PA_BODY_INC) {
            idx = idx + 1;
            pc = PA_CHECK;
        } else if (pc == PA_HALT_YES) {
            return 1;
        } else if (pc == PA_HALT_NO) {
            return 0;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_palindrome_loop(0x18)=%d vm_palindrome_loop(0x55)=%d\n",
           vm_palindrome_loop_target(0x18), vm_palindrome_loop_target(0x55));
    return 0;
}
```
