# vm_i64_return_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_i64_return_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_i64_return_loop.ll`
- **Symbol:** `vm_i64_return_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_i64_return_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_i64_return_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0, n=1: zero state stays zero |
| 2 | RCX=1 | 16088033396387240378 | 16088033396387240378 | 16088033396387240378 | yes | x=1, n=2 |
| 3 | RCX=7 | 17772545941868383875 | 17772545941868383875 | 17772545941868383875 | yes | x=7, n=8 max |
| 4 | RCX=255 | 10714506007073860731 | 10714506007073860731 | 10714506007073860731 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 17920236122590421895 | 17920236122590421895 | 17920236122590421895 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 11342307580973665351 | 11342307580973665351 | 11342307580973665351 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 14500037712827550128 | 14500037712827550128 | 14500037712827550128 | yes | x=0x123456789ABCDEF0, n=1 |
| 8 | RCX=18446744073709551615 | 13834830826346695547 | 13834830826346695547 | 13834830826346695547 | yes | max u64, n=8 |
| 9 | RCX=9223372036854775808 | 9223372036854775808 | 9223372036854775808 | 9223372036854775808 | yes | x=0x8000_0000_0000_0000, n=1: K*2^63 wraps to 0 |
| 10 | RCX=11400714819323198485 | 1102746351861860268 | 1102746351861860268 | 1102746351861860268 | yes | x=K (golden ratio), n=6 |

## Source

```c
/* PC-state VM that returns a FULL uint64_t, not the typical i32-narrowed
 * result.  Runs a Knuth-mixer recurrence
 *   state = state * 0x9E3779B97F4A7C15 + i
 * for n = (x & 7) + 1 iterations starting from state = x.
 * Lift target: vm_i64_return_loop_target.
 *
 * Distinct from existing i64 samples (vm_int64_loop / vm_shift64_loop /
 * vm_u64_array_loop) which mask to i32 at the return boundary; here the
 * lifted function's i64 return is the actual semantic value, exercising
 * the full 64-bit return-value path through the lifter.
 */
#include <stdio.h>
#include <stdint.h>

enum I64rVmPc {
    I64R_LOAD       = 0,
    I64R_INIT       = 1,
    I64R_LOOP_CHECK = 2,
    I64R_LOOP_BODY  = 3,
    I64R_LOOP_INC   = 4,
    I64R_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_i64_return_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = I64R_LOAD;

    while (1) {
        if (pc == I64R_LOAD) {
            n     = (int)(x & 7u) + 1;
            state = x;
            pc = I64R_INIT;
        } else if (pc == I64R_INIT) {
            idx = 0;
            pc = I64R_LOOP_CHECK;
        } else if (pc == I64R_LOOP_CHECK) {
            pc = (idx < n) ? I64R_LOOP_BODY : I64R_HALT;
        } else if (pc == I64R_LOOP_BODY) {
            state = state * 0x9E3779B97F4A7C15ull + (uint64_t)idx;
            pc = I64R_LOOP_INC;
        } else if (pc == I64R_LOOP_INC) {
            idx = idx + 1;
            pc = I64R_LOOP_CHECK;
        } else if (pc == I64R_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_i64_return(1)=0x%llx vm_i64_return(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_i64_return_loop_target(1ull),
           (unsigned long long)vm_i64_return_loop_target(0xCAFEull));
    return 0;
}
```
