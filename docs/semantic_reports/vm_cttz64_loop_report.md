# vm_cttz64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_cttz64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_cttz64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_cttz64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_cttz64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_cttz64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 64 | 64 | — | **no** | x=0: special-case 64 |
| 2 | RCX=1 | 0 | 0 | — | **no** | x=1: 0 trailing zeros |
| 3 | RCX=2 | 1 | 1 | — | **no** | x=2: 1 |
| 4 | RCX=4 | 2 | 2 | — | **no** | x=4: 2 |
| 5 | RCX=8 | 3 | 3 | — | **no** | x=8: 3 |
| 6 | RCX=4294967296 | 32 | 32 | — | **no** | x=2^32: 32 |
| 7 | RCX=9223372036854775808 | 63 | 63 | — | **no** | x=2^63: 63 (max) |
| 8 | RCX=3405691582 | 1 | 1 | — | **no** | x=0xCAFEBABE: 1 |
| 9 | RCX=18446744073709551614 | 1 | 1 | — | **no** | x=max-1: 1 |
| 10 | RCX=11400714819323198485 | 0 | 0 | — | **no** | x=K (golden): 0 (odd) |

## Failure detail

### case 1: x=0: special-case 64

- inputs: `RCX=0`
- manifest expected: `64`
- native: `64`
- lifted: `—`

### case 2: x=1: 0 trailing zeros

- inputs: `RCX=1`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 3: x=2: 1

- inputs: `RCX=2`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 4: x=4: 2

- inputs: `RCX=4`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 5: x=8: 3

- inputs: `RCX=8`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 6: x=2^32: 32

- inputs: `RCX=4294967296`
- manifest expected: `32`
- native: `32`
- lifted: `—`

### case 7: x=2^63: 63 (max)

- inputs: `RCX=9223372036854775808`
- manifest expected: `63`
- native: `63`
- lifted: `—`

### case 8: x=0xCAFEBABE: 1

- inputs: `RCX=3405691582`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 9: x=max-1: 1

- inputs: `RCX=18446744073709551614`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 10: x=K (golden): 0 (odd)

- inputs: `RCX=11400714819323198485`
- manifest expected: `0`
- native: `0`
- lifted: `—`

## Source

```c
/* PC-state VM running an i64 count-trailing-zeros via shift-loop.
 *   if (x == 0) return 64;
 *   count = 0;
 *   while ((x & 1) == 0) { x >>= 1; count++; }
 *   return count;
 * Variable trip count = ctz(x), bounded 0..63 (or short-circuit 64 for zero).
 * Lift target: vm_cttz64_loop_target.
 *
 * Distinct from vm_ctz_loop (i32) and vm_imported_cttz_loop (i32 _BitScanForward
 * intrinsic): exercises the same shape on full i64 with explicit shift-and-test
 * rather than the intrinsic.
 */
#include <stdio.h>
#include <stdint.h>

enum CzVmPc {
    CZ_LOAD       = 0,
    CZ_INIT       = 1,
    CZ_ZERO_CHECK = 2,
    CZ_LOOP_CHECK = 3,
    CZ_LOOP_BODY  = 4,
    CZ_HALT       = 5,
};

__declspec(noinline)
int vm_cttz64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = CZ_LOAD;

    while (1) {
        if (pc == CZ_LOAD) {
            state = x;
            count = 0;
            pc = CZ_ZERO_CHECK;
        } else if (pc == CZ_ZERO_CHECK) {
            if (state == 0ull) {
                count = 64;
                pc = CZ_HALT;
            } else {
                pc = CZ_LOOP_CHECK;
            }
        } else if (pc == CZ_LOOP_CHECK) {
            pc = ((state & 1ull) == 0ull) ? CZ_LOOP_BODY : CZ_HALT;
        } else if (pc == CZ_LOOP_BODY) {
            state = state >> 1;
            count = count + 1;
            pc = CZ_LOOP_CHECK;
        } else if (pc == CZ_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_cttz64(0x100000000)=%d vm_cttz64(0x8000000000000000)=%d\n",
           vm_cttz64_loop_target(0x100000000ull),
           vm_cttz64_loop_target(0x8000000000000000ull));
    return 0;
}
```
