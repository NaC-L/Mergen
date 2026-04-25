# vm_base7sum64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_base7sum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_base7sum64_loop.ll`
- **Symbol:** `vm_base7sum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_base7sum64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_base7sum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: skip loop |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: 1 in base 7 |
| 3 | RCX=7 | 1 | 1 | 1 | yes | x=7: 10 in base 7, sum=1 |
| 4 | RCX=48 | 12 | 12 | 12 | yes | x=48: 66 in base 7, sum=12 |
| 5 | RCX=49 | 1 | 1 | 1 | yes | x=49: 100 in base 7 |
| 6 | RCX=255 | 9 | 9 | 9 | yes | x=0xFF: 513 in base 7 |
| 7 | RCX=51966 | 18 | 18 | 18 | yes | x=0xCAFE |
| 8 | RCX=3405691582 | 40 | 40 | 40 | yes | x=0xCAFEBABE |
| 9 | RCX=18446744073709551615 | 57 | 57 | 57 | yes | max u64 |
| 10 | RCX=11400714819323198485 | 61 | 61 | 61 | yes | K (golden) |

## Source

```c
/* PC-state VM that computes the base-7 digit sum of x via repeated
 * urem-then-udiv.
 *   total = 0;
 *   while (s) { total += s % 7; s /= 7; }
 *   return total;
 * Variable trip ~= log_7(x).
 * Lift target: vm_base7sum64_loop_target.
 *
 * Distinct from vm_decdigits64_loop (counts digits, divisor 10) and
 * vm_divcount64_loop (input-derived divisor): exercises BOTH urem and
 * udiv by a small constant 7 inside the same loop body, accumulating
 * the running digit sum.
 */
#include <stdio.h>
#include <stdint.h>

enum B7VmPc {
    B7_LOAD       = 0,
    B7_LOOP_CHECK = 1,
    B7_LOOP_BODY  = 2,
    B7_HALT       = 3,
};

__declspec(noinline)
int vm_base7sum64_loop_target(uint64_t x) {
    uint64_t s     = 0;
    int      total = 0;
    int      pc    = B7_LOAD;

    while (1) {
        if (pc == B7_LOAD) {
            s     = x;
            total = 0;
            pc = B7_LOOP_CHECK;
        } else if (pc == B7_LOOP_CHECK) {
            pc = (s != 0ull) ? B7_LOOP_BODY : B7_HALT;
        } else if (pc == B7_LOOP_BODY) {
            total = total + (int)(s % 7ull);
            s = s / 7ull;
            pc = B7_LOOP_CHECK;
        } else if (pc == B7_HALT) {
            return total;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_base7sum64(0xCAFEBABE)=%d vm_base7sum64(max)=%d\n",
           vm_base7sum64_loop_target(0xCAFEBABEull),
           vm_base7sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
