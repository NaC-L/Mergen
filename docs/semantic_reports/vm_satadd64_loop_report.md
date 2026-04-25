# vm_satadd64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_satadd64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_satadd64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_satadd64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_satadd64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_satadd64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | — | **no** | x=0, inc=1, n=1: 0+1 |
| 2 | RCX=1 | 2 | 2 | — | **no** | x=1, inc=1, n=2 |
| 3 | RCX=7 | 56 | 56 | — | **no** | x=7, inc=7, n=8 |
| 4 | RCX=255 | 2040 | 2040 | — | **no** | x=0xFF, inc=0xFF, n=8 |
| 5 | RCX=9223372036854775809 | 18446744073709551615 | 18446744073709551615 | — | **no** | x=2^63+1, n=2: saturates iter2 |
| 6 | RCX=3405691582 | 23839841081 | 23839841081 | — | **no** | x=0xCAFEBABE: 7*0xCAFEBABF |
| 7 | RCX=1311768467463790320 | 1311768467463790321 | 1311768467463790321 | — | **no** | x=0x123...DEF0, n=1: single add |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | — | **no** | max u64: saturates iter2 |
| 9 | RCX=11400714819323198485 | 18446744073709551615 | 18446744073709551615 | — | **no** | K (golden, n=6): saturates |
| 10 | RCX=9223372036854775807 | 18446744073709551615 | 18446744073709551615 | — | **no** | INT64_MAX, n=8: saturates |

## Failure detail

### case 1: x=0, inc=1, n=1: 0+1

- inputs: `RCX=0`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 2: x=1, inc=1, n=2

- inputs: `RCX=1`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 3: x=7, inc=7, n=8

- inputs: `RCX=7`
- manifest expected: `56`
- native: `56`
- lifted: `—`

### case 4: x=0xFF, inc=0xFF, n=8

- inputs: `RCX=255`
- manifest expected: `2040`
- native: `2040`
- lifted: `—`

### case 5: x=2^63+1, n=2: saturates iter2

- inputs: `RCX=9223372036854775809`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 6: x=0xCAFEBABE: 7*0xCAFEBABF

- inputs: `RCX=3405691582`
- manifest expected: `23839841081`
- native: `23839841081`
- lifted: `—`

### case 7: x=0x123...DEF0, n=1: single add

- inputs: `RCX=1311768467463790320`
- manifest expected: `1311768467463790321`
- native: `1311768467463790321`
- lifted: `—`

### case 8: max u64: saturates iter2

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 9: K (golden, n=6): saturates

- inputs: `RCX=11400714819323198485`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 10: INT64_MAX, n=8: saturates

- inputs: `RCX=9223372036854775807`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

## Source

```c
/* PC-state VM running an i64 saturating-add accumulator with overflow
 * detection.
 *   inc = x | 1; n = (x & 7) + 1; result = 0;
 *   for i in 0..n: { s = result + inc; if (s < result) result = MAX; else result = s; }
 *   return result;
 * Lift target: vm_satadd64_loop_target.
 *
 * Distinct from vm_saturating_loop (i32 saturating sum): exercises i64
 * unsigned-overflow detection (icmp ult i64) with branchy clamp inside
 * a variable-trip loop body on full uint64_t state.
 */
#include <stdio.h>
#include <stdint.h>

enum SaVmPc {
    SA_LOAD       = 0,
    SA_INIT       = 1,
    SA_LOOP_CHECK = 2,
    SA_LOOP_BODY  = 3,
    SA_LOOP_INC   = 4,
    SA_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_satadd64_loop_target(uint64_t x) {
    int      idx    = 0;
    int      n      = 0;
    uint64_t inc    = 0;
    uint64_t result = 0;
    int      pc     = SA_LOAD;

    while (1) {
        if (pc == SA_LOAD) {
            inc    = x | 1ull;
            n      = (int)(x & 7ull) + 1;
            result = 0ull;
            pc = SA_INIT;
        } else if (pc == SA_INIT) {
            idx = 0;
            pc = SA_LOOP_CHECK;
        } else if (pc == SA_LOOP_CHECK) {
            pc = (idx < n) ? SA_LOOP_BODY : SA_HALT;
        } else if (pc == SA_LOOP_BODY) {
            uint64_t s = result + inc;
            if (s < result) {
                result = 0xFFFFFFFFFFFFFFFFull;
            } else {
                result = s;
            }
            pc = SA_LOOP_INC;
        } else if (pc == SA_LOOP_INC) {
            idx = idx + 1;
            pc = SA_LOOP_CHECK;
        } else if (pc == SA_HALT) {
            return result;
        } else {
            return 0ull;
        }
    }
}

int main(void) {
    printf("vm_satadd64(0x8000000000000001)=%llu vm_satadd64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_satadd64_loop_target(0x8000000000000001ull),
           (unsigned long long)vm_satadd64_loop_target(0xCAFEBABEull));
    return 0;
}
```
