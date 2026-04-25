# vm_bitreverse64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bitreverse64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_bitreverse64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bitreverse64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_bitreverse64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bitreverse64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0: zero stays zero |
| 2 | RCX=1 | 9223372036854775808 | 9223372036854775808 | — | **no** | x=1 -> MSB |
| 3 | RCX=255 | 18374686479671623680 | 18374686479671623680 | — | **no** | x=0xFF -> top byte |
| 4 | RCX=9223372036854775808 | 1 | 1 | — | **no** | x=2^63 -> 1 (MSB to LSB) |
| 5 | RCX=51966 | 9174676865883832320 | 9174676865883832320 | — | **no** | x=0xCAFE |
| 6 | RCX=3405691582 | 9033516422034096128 | 9033516422034096128 | — | **no** | x=0xCAFEBABE |
| 7 | RCX=1311768467463790320 | 1115552785675988040 | 1115552785675988040 | — | **no** | 0x123...DEF0 |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | — | **no** | max u64: bitreverse fixed point |
| 9 | RCX=11400714819323198485 | 12123218500447562873 | 12123218500447562873 | — | **no** | x=K (golden ratio) |
| 10 | RCX=12297829382473034410 | 6148914691236517205 | 6148914691236517205 | — | **no** | 0xAAAA... -> 0x5555... |

## Failure detail

### case 1: x=0: zero stays zero

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 -> MSB

- inputs: `RCX=1`
- manifest expected: `9223372036854775808`
- native: `9223372036854775808`
- lifted: `—`

### case 3: x=0xFF -> top byte

- inputs: `RCX=255`
- manifest expected: `18374686479671623680`
- native: `18374686479671623680`
- lifted: `—`

### case 4: x=2^63 -> 1 (MSB to LSB)

- inputs: `RCX=9223372036854775808`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 5: x=0xCAFE

- inputs: `RCX=51966`
- manifest expected: `9174676865883832320`
- native: `9174676865883832320`
- lifted: `—`

### case 6: x=0xCAFEBABE

- inputs: `RCX=3405691582`
- manifest expected: `9033516422034096128`
- native: `9033516422034096128`
- lifted: `—`

### case 7: 0x123...DEF0

- inputs: `RCX=1311768467463790320`
- manifest expected: `1115552785675988040`
- native: `1115552785675988040`
- lifted: `—`

### case 8: max u64: bitreverse fixed point

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 9: x=K (golden ratio)

- inputs: `RCX=11400714819323198485`
- manifest expected: `12123218500447562873`
- native: `12123218500447562873`
- lifted: `—`

### case 10: 0xAAAA... -> 0x5555...

- inputs: `RCX=12297829382473034410`
- manifest expected: `6148914691236517205`
- native: `6148914691236517205`
- lifted: `—`

## Source

```c
/* PC-state VM running an i64 bit-reverse via a 64-trip shift+or loop.
 *   result = 0;
 *   for i in 0..64:
 *     result = (result << 1) | (state & 1);
 *     state  = state >> 1;
 *   return result;
 * Lift target: vm_bitreverse64_loop_target.
 *
 * Distinct from vm_bitreverse_loop (i32 version, lifter recognizes
 * llvm.bitreverse.i8): exercises a 64-trip explicit fan-in shift+or +
 * shift-right body on full i64 state.  May or may not be recognized as
 * llvm.bitreverse.i64 by the optimizer.
 */
#include <stdio.h>
#include <stdint.h>

enum BrVmPc {
    BR_LOAD       = 0,
    BR_INIT       = 1,
    BR_LOOP_CHECK = 2,
    BR_LOOP_BODY  = 3,
    BR_LOOP_INC   = 4,
    BR_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bitreverse64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t state  = 0;
    uint64_t result = 0;
    int      pc     = BR_LOAD;

    while (1) {
        if (pc == BR_LOAD) {
            state  = x;
            result = 0ull;
            pc = BR_INIT;
        } else if (pc == BR_INIT) {
            idx = 0;
            pc = BR_LOOP_CHECK;
        } else if (pc == BR_LOOP_CHECK) {
            pc = (idx < 64) ? BR_LOOP_BODY : BR_HALT;
        } else if (pc == BR_LOOP_BODY) {
            result = (result << 1) | (state & 1ull);
            state  = state >> 1;
            pc = BR_LOOP_INC;
        } else if (pc == BR_LOOP_INC) {
            idx = idx + 1;
            pc = BR_LOOP_CHECK;
        } else if (pc == BR_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bitreverse64(1)=0x%llx vm_bitreverse64(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_bitreverse64_loop_target(1ull),
           (unsigned long long)vm_bitreverse64_loop_target(0xCAFEull));
    return 0;
}
```
