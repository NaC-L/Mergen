# vm_divcount64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_divcount64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_divcount64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_divcount64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_divcount64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_divcount64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 63 | 63 | — | **no** | x=0: ~x=max u64, div=2 -> 63 halvings |
| 2 | RCX=1 | 40 | 40 | — | **no** | x=1: div=3, log_3(max-1) |
| 3 | RCX=2 | 31 | 31 | — | **no** | x=2: div=4, log_4(max-2) |
| 4 | RCX=255 | 7 | 7 | — | **no** | x=0xFF: div=257, log_257(max-255) |
| 5 | RCX=51966 | 7 | 7 | — | **no** | x=0xCAFE: div=256 |
| 6 | RCX=3405691582 | 8 | 8 | — | **no** | x=0xCAFEBABE: div=192 |
| 7 | RCX=1311768467463790320 | 8 | 8 | — | **no** | x=0x123...DEF0: div=242 |
| 8 | RCX=18446744073709551615 | 0 | 0 | — | **no** | max u64: ~x=0 < div, count=0 |
| 9 | RCX=11400714819323198485 | 13 | 13 | — | **no** | x=K: div=23, log_23 |
| 10 | RCX=3735928559 | 8 | 8 | — | **no** | x=0xDEADBEEF: div=241 |

## Failure detail

### case 1: x=0: ~x=max u64, div=2 -> 63 halvings

- inputs: `RCX=0`
- manifest expected: `63`
- native: `63`
- lifted: `—`

### case 2: x=1: div=3, log_3(max-1)

- inputs: `RCX=1`
- manifest expected: `40`
- native: `40`
- lifted: `—`

### case 3: x=2: div=4, log_4(max-2)

- inputs: `RCX=2`
- manifest expected: `31`
- native: `31`
- lifted: `—`

### case 4: x=0xFF: div=257, log_257(max-255)

- inputs: `RCX=255`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=0xCAFE: div=256

- inputs: `RCX=51966`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 6: x=0xCAFEBABE: div=192

- inputs: `RCX=3405691582`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 7: x=0x123...DEF0: div=242

- inputs: `RCX=1311768467463790320`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 8: max u64: ~x=0 < div, count=0

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 9: x=K: div=23, log_23

- inputs: `RCX=11400714819323198485`
- manifest expected: `13`
- native: `13`
- lifted: `—`

### case 10: x=0xDEADBEEF: div=241

- inputs: `RCX=3735928559`
- manifest expected: `8`
- native: `8`
- lifted: `—`

## Source

```c
/* PC-state VM that counts how many times an i64 state can be divided
 * by an input-derived divisor before it falls below the divisor.
 *   divisor = (x & 0xFF) + 2;   // 2..257, never zero
 *   state   = ~x;
 *   count   = 0;
 *   while (state >= divisor) { state /= divisor; count++; }
 *   return count;
 * Lift target: vm_divcount64_loop_target.
 *
 * Distinct from vm_gcd64_loop (urem-driven Euclidean): exercises
 * repeated i64 udiv inside a data-dependent loop (variable trip 0..63
 * depending on log_{divisor}(state)).
 */
#include <stdio.h>
#include <stdint.h>

enum DvVmPc {
    DV_LOAD       = 0,
    DV_LOOP_CHECK = 1,
    DV_LOOP_BODY  = 2,
    DV_HALT       = 3,
};

__declspec(noinline)
int vm_divcount64_loop_target(uint64_t x) {
    uint64_t divisor = 0;
    uint64_t state   = 0;
    int      count   = 0;
    int      pc      = DV_LOAD;

    while (1) {
        if (pc == DV_LOAD) {
            divisor = (x & 0xFFull) + 2ull;
            state   = ~x;
            count   = 0;
            pc = DV_LOOP_CHECK;
        } else if (pc == DV_LOOP_CHECK) {
            pc = (state >= divisor) ? DV_LOOP_BODY : DV_HALT;
        } else if (pc == DV_LOOP_BODY) {
            state = state / divisor;
            count = count + 1;
            pc = DV_LOOP_CHECK;
        } else if (pc == DV_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_divcount64(0)=%d vm_divcount64(0xCAFE)=%d\n",
           vm_divcount64_loop_target(0ull),
           vm_divcount64_loop_target(0xCAFEull));
    return 0;
}
```
