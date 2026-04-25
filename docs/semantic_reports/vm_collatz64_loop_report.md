# vm_collatz64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_collatz64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_collatz64_loop.ll`
- **Symbol:** `vm_collatz64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_collatz64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_collatz64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=1 | 0 | 0 | 0 | yes | x=1: zero steps |
| 2 | RCX=2 | 1 | 1 | 1 | yes | x=2: one halving |
| 3 | RCX=3 | 7 | 7 | 7 | yes | x=3: 7 steps |
| 4 | RCX=6 | 8 | 8 | 8 | yes | x=6: 8 steps |
| 5 | RCX=27 | 111 | 111 | 111 | yes | x=27: classic 111-step Collatz |
| 6 | RCX=51966 | 171 | 171 | 171 | yes | x=0xCAFE |
| 7 | RCX=4294967296 | 32 | 32 | 32 | yes | x=2^32: 32 halvings |
| 8 | RCX=18446744073709551614 | 618 | 618 | 618 | yes | max u64 - 1: 618 steps incl. mul-wrap |
| 9 | RCX=9223372036854775808 | 63 | 63 | 63 | yes | x=2^63: 63 halvings |
| 10 | RCX=11400714819323198485 | 414 | 414 | 414 | yes | x=K (golden ratio): 414 steps |

## Source

```c
/* PC-state VM running the Collatz sequence on a FULL uint64_t state.
 *   while (state != 1) { state = (state & 1) ? 3*state + 1 : state / 2; count++; }
 * Trip count is data-dependent on the input.  3*x+1 wraps mod 2^64 for
 * very large inputs but Collatz still converges within bounded steps.
 * Lift target: vm_collatz64_loop_target.
 *
 * Distinct from vm_collatz_loop (i32 Collatz): exercises the same
 * algorithm shape on full 64-bit state with i64 udiv (lshr-by-1) and
 * i64 mul-by-3 + add operations.
 */
#include <stdio.h>
#include <stdint.h>

enum C64VmPc {
    C64_LOAD       = 0,
    C64_LOOP_CHECK = 1,
    C64_LOOP_BODY  = 2,
    C64_HALT       = 3,
};

__declspec(noinline)
int vm_collatz64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = C64_LOAD;

    while (1) {
        if (pc == C64_LOAD) {
            state = x;
            count = 0;
            pc = C64_LOOP_CHECK;
        } else if (pc == C64_LOOP_CHECK) {
            pc = (state != 1ull) ? C64_LOOP_BODY : C64_HALT;
        } else if (pc == C64_LOOP_BODY) {
            if ((state & 1ull) == 0ull) {
                state = state >> 1;
            } else {
                state = state * 3ull + 1ull;
            }
            count = count + 1;
            pc = C64_LOOP_CHECK;
        } else if (pc == C64_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_collatz64(27)=%d vm_collatz64(0xCAFE)=%d\n",
           vm_collatz64_loop_target(27ull),
           vm_collatz64_loop_target(0xCAFEull));
    return 0;
}
```
