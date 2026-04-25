# vm_xorbytes64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xorbytes64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_xorbytes64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xorbytes64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_xorbytes64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xorbytes64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1: only low byte |
| 3 | RCX=255 | 255 | 255 | — | **no** | x=0xFF: low byte = 0xFF |
| 4 | RCX=51966 | 52 | 52 | — | **no** | x=0xCAFE: 0xFE^0xCA=0x34 |
| 5 | RCX=3405691582 | 48 | 48 | — | **no** | 0xCAFEBABE |
| 6 | RCX=1311768467463790320 | 0 | 0 | — | **no** | 0x123456789ABCDEF0: bytes XOR cancel |
| 7 | RCX=18446744073709551615 | 0 | 0 | — | **no** | max u64: 8x0xFF cancel |
| 8 | RCX=11400714819323198485 | 53 | 53 | — | **no** | K (golden) |
| 9 | RCX=170 | 170 | 170 | — | **no** | x=0xAA: only low byte |
| 10 | RCX=71777214294589695 | 0 | 0 | — | **no** | 0x00FF00FF00FF00FF: 4x0xFF cancel |

## Failure detail

### case 1: x=0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1: only low byte

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=0xFF: low byte = 0xFF

- inputs: `RCX=255`
- manifest expected: `255`
- native: `255`
- lifted: `—`

### case 4: x=0xCAFE: 0xFE^0xCA=0x34

- inputs: `RCX=51966`
- manifest expected: `52`
- native: `52`
- lifted: `—`

### case 5: 0xCAFEBABE

- inputs: `RCX=3405691582`
- manifest expected: `48`
- native: `48`
- lifted: `—`

### case 6: 0x123456789ABCDEF0: bytes XOR cancel

- inputs: `RCX=1311768467463790320`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 7: max u64: 8x0xFF cancel

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 8: K (golden)

- inputs: `RCX=11400714819323198485`
- manifest expected: `53`
- native: `53`
- lifted: `—`

### case 9: x=0xAA: only low byte

- inputs: `RCX=170`
- manifest expected: `170`
- native: `170`
- lifted: `—`

### case 10: 0x00FF00FF00FF00FF: 4x0xFF cancel

- inputs: `RCX=71777214294589695`
- manifest expected: `0`
- native: `0`
- lifted: `—`

## Source

```c
/* PC-state VM that XOR-folds all 8 bytes of x into a single byte.
 *   result = 0;
 *   for i in 0..8: result ^= (x >> (i*8)) & 0xFF;
 *   return result;     // only low 8 bits non-zero
 * 8-trip fixed loop with byte-walking shift (loop-counter * 8).
 * Lift target: vm_xorbytes64_loop_target.
 *
 * Distinct from vm_djb264_loop (multiplicative byte hash) and
 * vm_morton64_loop (1-bit fan-out spread): exercises an XOR-reduction
 * over byte slices with no multiplication.  Even-byte-count duplicates
 * cancel to zero; result is a single-byte XOR signature.
 */
#include <stdio.h>
#include <stdint.h>

enum XbVmPc {
    XB_LOAD       = 0,
    XB_INIT       = 1,
    XB_LOOP_CHECK = 2,
    XB_LOOP_BODY  = 3,
    XB_LOOP_INC   = 4,
    XB_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xorbytes64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t result = 0;
    int      pc     = XB_LOAD;

    while (1) {
        if (pc == XB_LOAD) {
            xx     = x;
            result = 0ull;
            pc = XB_INIT;
        } else if (pc == XB_INIT) {
            idx = 0;
            pc = XB_LOOP_CHECK;
        } else if (pc == XB_LOOP_CHECK) {
            pc = (idx < 8) ? XB_LOOP_BODY : XB_HALT;
        } else if (pc == XB_LOOP_BODY) {
            result = result ^ ((xx >> (idx * 8)) & 0xFFull);
            pc = XB_LOOP_INC;
        } else if (pc == XB_LOOP_INC) {
            idx = idx + 1;
            pc = XB_LOOP_CHECK;
        } else if (pc == XB_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorbytes64(0xCAFEBABE)=%llu vm_xorbytes64(0x9E3779B97F4A7C15)=%llu\n",
           (unsigned long long)vm_xorbytes64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_xorbytes64_loop_target(0x9E3779B97F4A7C15ull));
    return 0;
}
```
