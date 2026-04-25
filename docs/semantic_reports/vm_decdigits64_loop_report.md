# vm_decdigits64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_decdigits64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_decdigits64_loop.ll`
- **Symbol:** `vm_decdigits64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_decdigits64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_decdigits64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | x=0: special-case 1 digit |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 |
| 3 | RCX=10 | 2 | 2 | 2 | yes | x=10 |
| 4 | RCX=100 | 3 | 3 | 3 | yes | x=100 |
| 5 | RCX=999 | 3 | 3 | 3 | yes | x=999 |
| 6 | RCX=1000 | 4 | 4 | 4 | yes | x=1000 |
| 7 | RCX=1000000000 | 10 | 10 | 10 | yes | x=10^9 |
| 8 | RCX=51966 | 5 | 5 | 5 | yes | x=0xCAFE = 51966 |
| 9 | RCX=18446744073709551615 | 20 | 20 | 20 | yes | max u64: 20 digits |
| 10 | RCX=11400714819323198485 | 20 | 20 | 20 | yes | K (golden), 20 digits |

## Source

```c
/* PC-state VM that counts decimal digits of a uint64_t via repeated /10.
 *   if (x == 0) return 1;
 *   count = 0;
 *   while (state > 0) { state /= 10; count++; }
 *   return count;
 * Variable trip 1..20 (up to 20 for max u64).
 * Lift target: vm_decdigits64_loop_target.
 *
 * Distinct from vm_divcount64_loop (input-derived divisor with >=
 * comparison) and vm_sdiv64_loop: this uses a fixed constant divisor 10
 * with a > 0 termination, exercising i64 udiv-by-constant inside a
 * data-dependent loop.  Lifter likely emits magic-number multiplication
 * fold for /10, but loop count remains data-dependent.
 */
#include <stdio.h>
#include <stdint.h>

enum DdVmPc {
    DD_LOAD       = 0,
    DD_ZERO_CHECK = 1,
    DD_LOOP_CHECK = 2,
    DD_LOOP_BODY  = 3,
    DD_HALT       = 4,
};

__declspec(noinline)
int vm_decdigits64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = DD_LOAD;

    while (1) {
        if (pc == DD_LOAD) {
            state = x;
            count = 0;
            pc = DD_ZERO_CHECK;
        } else if (pc == DD_ZERO_CHECK) {
            if (state == 0ull) {
                count = 1;
                pc = DD_HALT;
            } else {
                pc = DD_LOOP_CHECK;
            }
        } else if (pc == DD_LOOP_CHECK) {
            pc = (state > 0ull) ? DD_LOOP_BODY : DD_HALT;
        } else if (pc == DD_LOOP_BODY) {
            state = state / 10ull;
            count = count + 1;
            pc = DD_LOOP_CHECK;
        } else if (pc == DD_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_decdigits64(0xCAFEBABE)=%d vm_decdigits64(max)=%d\n",
           vm_decdigits64_loop_target(0xCAFEBABEull),
           vm_decdigits64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
