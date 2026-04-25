# vm_imported_bswap_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 11/11 passed
- **Source:** `testcases/rewrite_smoke/vm_imported_bswap_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_bswap_loop.ll`
- **Symbol:** `vm_imported_bswap_loop_target`
- **IR size:** 53 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 1 | 1 | pass | limit=1, x=0 |
| 2 | RCX=1 | 33554435 | 33554435 | pass | limit=2, x=1 |
| 3 | RCX=7 | 939524132 | 939524132 | pass | limit=8, x=7 |
| 4 | RCX=255 | 4160749604 | 4160749604 | pass | 0xFF: limit=8 |
| 5 | RCX=256 | 65537 | 65537 | pass | 0x100: limit=1 |
| 6 | RCX=51966 | 4152754204 | 4152754204 | pass | 0xCAFE: limit=7 |
| 7 | RCX=43981 | 3523346453 | 3523346453 | pass | 0xABCD: limit=6 |
| 8 | RCX=74565 | 2664564245 | 2664564245 | pass | 0x12345: limit=6 |
| 9 | RCX=-1 | 4294967252 | 4294967252 | pass | 0xFFFFFFFF: limit=8 |
| 10 | RCX=-559038737 | 2113236692 | 2113236692 | pass | 0xDEADBEEF: limit=8 |
| 11 | RCX=128 | 2147483649 | 2147483649 | pass | 0x80: limit=1 |

## Source

```c
/* PC-state VM whose body calls __builtin_bswap32 (lowered by clang to
 * @llvm.bswap.i32) on x XOR'd with a per-iteration shift constant.
 * Lift target: vm_imported_bswap_loop_target.
 * Goal: cover a fourth recognized-intrinsic shape.  bswap exercises the
 * lifter's byte-permutation lowering inside a VM dispatcher.
 */
#include <stdio.h>

enum BwVmPc {
    BW_LOAD       = 0,
    BW_INIT       = 1,
    BW_CHECK      = 2,
    BW_BODY_XOR   = 3,
    BW_BODY_CALL  = 4,
    BW_BODY_ADD   = 5,
    BW_BODY_INC   = 6,
    BW_HALT       = 7,
};

__declspec(noinline)
int vm_imported_bswap_loop_target(int x) {
    unsigned limit = 0;
    unsigned idx   = 0;
    unsigned sum   = 0;
    unsigned v     = 0;
    unsigned bs    = 0;
    int pc         = BW_LOAD;

    while (1) {
        if (pc == BW_LOAD) {
            limit = ((unsigned)x & 7) + 1;
            sum = 0;
            pc = BW_INIT;
        } else if (pc == BW_INIT) {
            idx = 0;
            pc = BW_CHECK;
        } else if (pc == BW_CHECK) {
            pc = (idx < limit) ? BW_BODY_XOR : BW_HALT;
        } else if (pc == BW_BODY_XOR) {
            v = (unsigned)x ^ ((idx + 1) << 24);
            pc = BW_BODY_CALL;
        } else if (pc == BW_BODY_CALL) {
            bs = __builtin_bswap32(v);
            pc = BW_BODY_ADD;
        } else if (pc == BW_BODY_ADD) {
            sum = sum + bs;
            pc = BW_BODY_INC;
        } else if (pc == BW_BODY_INC) {
            idx = idx + 1;
            pc = BW_CHECK;
        } else if (pc == BW_HALT) {
            return (int)sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_bswap_loop(0xDEADBEEF)=%u vm_imported_bswap_loop(0xFF)=%u\n",
           (unsigned)vm_imported_bswap_loop_target((int)0xDEADBEEFu),
           (unsigned)vm_imported_bswap_loop_target(0xFF));
    return 0;
}
```
