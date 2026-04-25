# vm_bswap64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bswap64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_bswap64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bswap64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_bswap64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bswap64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0: zero stays zero |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1, n=2: double bswap = identity |
| 3 | RCX=2 | 144115188075855872 | 144115188075855872 | — | **no** | x=2, n=3: bswap once -> 0x0200...0 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7, n=8: even -> identity |
| 5 | RCX=255 | 255 | 255 | — | **no** | x=0xFF, n=8: even -> identity |
| 6 | RCX=51966 | 18359486830929248256 | 18359486830929248256 | — | **no** | x=0xCAFE, n=7 (odd) -> 0xFECA00..0 |
| 7 | RCX=3405691582 | 13743577356411338752 | 13743577356411338752 | — | **no** | x=0xCAFEBABE, n=7 (odd) |
| 8 | RCX=1311768467463790320 | 17356517385562371090 | 17356517385562371090 | — | **no** | 0x123...DEF0, n=1: bswap once |
| 9 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | — | **no** | max u64: bswap fixed point |
| 10 | RCX=11400714819323198485 | 11400714819323198485 | 11400714819323198485 | — | **no** | K (golden): n=6 even -> identity |

## Failure detail

### case 1: x=0: zero stays zero

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1, n=2: double bswap = identity

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2, n=3: bswap once -> 0x0200...0

- inputs: `RCX=2`
- manifest expected: `144115188075855872`
- native: `144115188075855872`
- lifted: `—`

### case 4: x=7, n=8: even -> identity

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=0xFF, n=8: even -> identity

- inputs: `RCX=255`
- manifest expected: `255`
- native: `255`
- lifted: `—`

### case 6: x=0xCAFE, n=7 (odd) -> 0xFECA00..0

- inputs: `RCX=51966`
- manifest expected: `18359486830929248256`
- native: `18359486830929248256`
- lifted: `—`

### case 7: x=0xCAFEBABE, n=7 (odd)

- inputs: `RCX=3405691582`
- manifest expected: `13743577356411338752`
- native: `13743577356411338752`
- lifted: `—`

### case 8: 0x123...DEF0, n=1: bswap once

- inputs: `RCX=1311768467463790320`
- manifest expected: `17356517385562371090`
- native: `17356517385562371090`
- lifted: `—`

### case 9: max u64: bswap fixed point

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 10: K (golden): n=6 even -> identity

- inputs: `RCX=11400714819323198485`
- manifest expected: `11400714819323198485`
- native: `11400714819323198485`
- lifted: `—`

## Source

```c
/* PC-state VM running an i64 byte-swap built from explicit shifts and
 * masks (no intrinsic) in a variable-trip loop.  Even-trip values produce
 * identity; odd-trip values produce a single byte-swap of the input.
 *   for i in 0..n: state = byteswap_via_shifts_and_masks(state)
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_bswap64_loop_target.
 *
 * Distinct from vm_imported_bswap_loop (i32 _byteswap_ulong intrinsic):
 * exercises the explicit 8-way mask+shift+or fan-in lowering on full i64
 * state.  The lifter likely recognizes this as llvm.bswap.i64 after
 * optimization.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_LOAD       = 0,
    BS_INIT       = 1,
    BS_LOOP_CHECK = 2,
    BS_LOOP_BODY  = 3,
    BS_LOOP_INC   = 4,
    BS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bswap64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = BS_LOAD;

    while (1) {
        if (pc == BS_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = BS_INIT;
        } else if (pc == BS_INIT) {
            idx = 0;
            pc = BS_LOOP_CHECK;
        } else if (pc == BS_LOOP_CHECK) {
            pc = (idx < n) ? BS_LOOP_BODY : BS_HALT;
        } else if (pc == BS_LOOP_BODY) {
            state = ((state & 0x00000000000000FFull) << 56) |
                    ((state & 0x000000000000FF00ull) << 40) |
                    ((state & 0x0000000000FF0000ull) << 24) |
                    ((state & 0x00000000FF000000ull) << 8)  |
                    ((state & 0x000000FF00000000ull) >> 8)  |
                    ((state & 0x0000FF0000000000ull) >> 24) |
                    ((state & 0x00FF000000000000ull) >> 40) |
                    ((state & 0xFF00000000000000ull) >> 56);
            pc = BS_LOOP_INC;
        } else if (pc == BS_LOOP_INC) {
            idx = idx + 1;
            pc = BS_LOOP_CHECK;
        } else if (pc == BS_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bswap64(0x123456789ABCDEF0)=0x%llx vm_bswap64(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_bswap64_loop_target(0x123456789ABCDEF0ull),
           (unsigned long long)vm_bswap64_loop_target(0xCAFEull));
    return 0;
}
```
