# vm_rotl64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_rotl64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_rotl64_loop.ll`
- **Symbol:** `vm_rotl64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_rotl64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_rotl64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: zero stays zero |
| 2 | RCX=1 | 4 | 4 | 4 | yes | x=1, amount=2, n=1 |
| 3 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | max u64: rotation invariant |
| 4 | RCX=9223372036854775808 | 1 | 1 | 1 | yes | x=2^63, amount=1: MSB->LSB |
| 5 | RCX=51966 | 18302628885633695946 | 18302628885633695946 | 18302628885633695946 | yes | x=0xCAFE, amount=31, n=8 |
| 6 | RCX=3405691582 | 17870283321459342058 | 17870283321459342058 | 17870283321459342058 | yes | 0xCAFEBABE, amount=31, n=6 |
| 7 | RCX=1311768467463790320 | 3771334343958392850 | 3771334343958392850 | 3771334343958392850 | yes | 0x123456789ABCDEF0, amount=17, n=8 |
| 8 | RCX=7 | 1792 | 1792 | 1792 | yes | x=7, amount=8, n=1: byte shift |
| 9 | RCX=11400714819323198485 | 7953307047391890910 | 7953307047391890910 | 7953307047391890910 | yes | x=K (golden ratio), amount=22, n=1 |
| 10 | RCX=511 | 511 | 511 | 511 | yes | x=0x1FF, amount=32, n=8: rotation invariant for amount=32 since (lo<->hi) twice = identity but here 8 swaps = identity |

## Source

```c
/* PC-state VM running an iterated 64-bit left rotation.
 *   amount = (x & 0x1F) + 1     (range 1..32, safe for u64 shift)
 *   n      = ((x >> 5) & 7) + 1 (range 1..8)
 *   state  = x; for i in 0..n: state = rotl64(state, amount)
 * Returns the full uint64_t state.
 * Lift target: vm_rotl64_loop_target.
 *
 * Distinct from vm_imported_rotl_loop (i32 rotation via _rotl) and
 * vm_rotate_loop: this exercises 64-bit rotation in a variable-trip loop,
 * lowering through llvm.fshl.i64 (or shift+or pair) on i64 state.
 */
#include <stdio.h>
#include <stdint.h>

enum R64VmPc {
    R64_LOAD       = 0,
    R64_INIT       = 1,
    R64_LOOP_CHECK = 2,
    R64_LOOP_BODY  = 3,
    R64_LOOP_INC   = 4,
    R64_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_rotl64_loop_target(uint64_t x) {
    int      idx    = 0;
    int      n      = 0;
    int      amount = 0;
    uint64_t state  = 0;
    int      pc     = R64_LOAD;

    while (1) {
        if (pc == R64_LOAD) {
            amount = (int)(x & 0x1Full) + 1;
            n      = (int)((x >> 5) & 7ull) + 1;
            state  = x;
            pc = R64_INIT;
        } else if (pc == R64_INIT) {
            idx = 0;
            pc = R64_LOOP_CHECK;
        } else if (pc == R64_LOOP_CHECK) {
            pc = (idx < n) ? R64_LOOP_BODY : R64_HALT;
        } else if (pc == R64_LOOP_BODY) {
            state = (state << amount) | (state >> (64 - amount));
            pc = R64_LOOP_INC;
        } else if (pc == R64_LOOP_INC) {
            idx = idx + 1;
            pc = R64_LOOP_CHECK;
        } else if (pc == R64_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_rotl64(0xCAFE)=0x%llx vm_rotl64(0x123456789ABCDEF0)=0x%llx\n",
           (unsigned long long)vm_rotl64_loop_target(0xCAFEull),
           (unsigned long long)vm_rotl64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
```
