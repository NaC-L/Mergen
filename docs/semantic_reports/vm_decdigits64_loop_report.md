# vm_decdigits64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_decdigits64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_decdigits64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_decdigits64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_decdigits64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_decdigits64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | — | **no** | x=0: special-case 1 digit |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 |
| 3 | RCX=10 | 2 | 2 | — | **no** | x=10 |
| 4 | RCX=100 | 3 | 3 | — | **no** | x=100 |
| 5 | RCX=999 | 3 | 3 | — | **no** | x=999 |
| 6 | RCX=1000 | 4 | 4 | — | **no** | x=1000 |
| 7 | RCX=1000000000 | 10 | 10 | — | **no** | x=10^9 |
| 8 | RCX=51966 | 5 | 5 | — | **no** | x=0xCAFE = 51966 |
| 9 | RCX=18446744073709551615 | 20 | 20 | — | **no** | max u64: 20 digits |
| 10 | RCX=11400714819323198485 | 20 | 20 | — | **no** | K (golden), 20 digits |

## Failure detail

### case 1: x=0: special-case 1 digit

- inputs: `RCX=0`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 2: x=1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=10

- inputs: `RCX=10`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=100

- inputs: `RCX=100`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 5: x=999

- inputs: `RCX=999`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 6: x=1000

- inputs: `RCX=1000`
- manifest expected: `4`
- native: `4`
- lifted: `—`

### case 7: x=10^9

- inputs: `RCX=1000000000`
- manifest expected: `10`
- native: `10`
- lifted: `—`

### case 8: x=0xCAFE = 51966

- inputs: `RCX=51966`
- manifest expected: `5`
- native: `5`
- lifted: `—`

### case 9: max u64: 20 digits

- inputs: `RCX=18446744073709551615`
- manifest expected: `20`
- native: `20`
- lifted: `—`

### case 10: K (golden), 20 digits

- inputs: `RCX=11400714819323198485`
- manifest expected: `20`
- native: `20`
- lifted: `—`

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
