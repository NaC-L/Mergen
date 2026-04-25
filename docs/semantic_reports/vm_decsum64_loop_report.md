# vm_decsum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_decsum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_decsum64_loop.ll`
- **Symbol:** `vm_decsum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_decsum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_decsum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: skip loop |
| 2 | RCX=5 | 5 | 5 | 5 | yes | x=5 |
| 3 | RCX=99 | 18 | 18 | 18 | yes | x=99 |
| 4 | RCX=999 | 27 | 27 | 27 | yes | x=999 |
| 5 | RCX=12345 | 15 | 15 | 15 | yes | x=12345 |
| 6 | RCX=1234567890 | 45 | 45 | 45 | yes | 1+2+...+9+0 |
| 7 | RCX=9999999999999999999 | 171 | 171 | 171 | yes | 19 nines |
| 8 | RCX=18446744073709551615 | 87 | 87 | 87 | yes | max u64 |
| 9 | RCX=11400714819323198485 | 79 | 79 | 79 | yes | K (golden) |
| 10 | RCX=3405691582 | 43 | 43 | 43 | yes | x=0xCAFEBABE = 3405691582 dec |

## Source

```c
/* PC-state VM that computes the base-10 decimal digit SUM of x.
 *   total = 0;
 *   while (s) { total += s % 10; s /= 10; }
 *   return total;
 * Variable trip = number of decimal digits.
 * Lift target: vm_decsum64_loop_target.
 *
 * Distinct from vm_base7sum64_loop (digit sum base 7) and
 * vm_digitprod64_loop (digit PRODUCT base 10): pure additive digit
 * accumulator with udiv-by-10 + urem-by-10 inside body.  Max value for
 * max u64 is 87 (sum of digits of 18446744073709551615).
 */
#include <stdio.h>
#include <stdint.h>

enum DsVmPc {
    DS_LOAD       = 0,
    DS_LOOP_CHECK = 1,
    DS_LOOP_BODY  = 2,
    DS_HALT       = 3,
};

__declspec(noinline)
int vm_decsum64_loop_target(uint64_t x) {
    uint64_t s     = 0;
    int      total = 0;
    int      pc    = DS_LOAD;

    while (1) {
        if (pc == DS_LOAD) {
            s     = x;
            total = 0;
            pc = DS_LOOP_CHECK;
        } else if (pc == DS_LOOP_CHECK) {
            pc = (s != 0ull) ? DS_LOOP_BODY : DS_HALT;
        } else if (pc == DS_LOOP_BODY) {
            total = total + (int)(s % 10ull);
            s = s / 10ull;
            pc = DS_LOOP_CHECK;
        } else if (pc == DS_HALT) {
            return total;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_decsum64(12345)=%d vm_decsum64(max)=%d\n",
           vm_decsum64_loop_target(12345ull),
           vm_decsum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
