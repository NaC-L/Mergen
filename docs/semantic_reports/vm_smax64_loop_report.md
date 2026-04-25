# vm_smax64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_smax64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_smax64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_smax64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_smax64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_smax64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0, n=1: max stays at val=0 (INT64_MIN beats nothing) |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1, n=2 |
| 3 | RCX=7 | 8709371129873690707 | 8709371129873690707 | — | **no** | x=7, n=8 |
| 4 | RCX=31 | 8709371129873690699 | 8709371129873690699 | — | **no** | x=0x1F, n=32 max |
| 5 | RCX=255 | 8709371129873690795 | 8709371129873690795 | — | **no** | x=0xFF, n=32 |
| 6 | RCX=51966 | 8709371129873644202 | 8709371129873644202 | — | **no** | x=0xCAFE, n=31 |
| 7 | RCX=3405691582 | 8709371126563162858 | 8709371126563162858 | — | **no** | x=0xCAFEBABE, n=31 |
| 8 | RCX=18446744073709551615 | 9102032882310693530 | 9102032882310693530 | — | **no** | max u64 (signed -1), n=32 |
| 9 | RCX=1311768467463790320 | 8695855810279968268 | 8695855810279968268 | — | **no** | 0x123...DEF0, n=17 |
| 10 | RCX=11400714819323198485 | 9025462342794460485 | 9025462342794460485 | — | **no** | K (golden), n=22 |

## Failure detail

### case 1: x=0, n=1: max stays at val=0 (INT64_MIN beats nothing)

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1, n=2

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=7, n=8

- inputs: `RCX=7`
- manifest expected: `8709371129873690707`
- native: `8709371129873690707`
- lifted: `—`

### case 4: x=0x1F, n=32 max

- inputs: `RCX=31`
- manifest expected: `8709371129873690699`
- native: `8709371129873690699`
- lifted: `—`

### case 5: x=0xFF, n=32

- inputs: `RCX=255`
- manifest expected: `8709371129873690795`
- native: `8709371129873690795`
- lifted: `—`

### case 6: x=0xCAFE, n=31

- inputs: `RCX=51966`
- manifest expected: `8709371129873644202`
- native: `8709371129873644202`
- lifted: `—`

### case 7: x=0xCAFEBABE, n=31

- inputs: `RCX=3405691582`
- manifest expected: `8709371126563162858`
- native: `8709371126563162858`
- lifted: `—`

### case 8: max u64 (signed -1), n=32

- inputs: `RCX=18446744073709551615`
- manifest expected: `9102032882310693530`
- native: `9102032882310693530`
- lifted: `—`

### case 9: 0x123...DEF0, n=17

- inputs: `RCX=1311768467463790320`
- manifest expected: `8695855810279968268`
- native: `8695855810279968268`
- lifted: `—`

### case 10: K (golden), n=22

- inputs: `RCX=11400714819323198485`
- manifest expected: `9025462342794460485`
- native: `9025462342794460485`
- lifted: `—`

## Source

```c
/* PC-state VM running an i64 SIGNED-max reduction over a derived
 * sequence.
 *   n = (x & 0x1F) + 1;
 *   m = INT64_MIN;
 *   for i in 0..n: { val = (int64_t)(x ^ (i * 0x9E3779B97F4A7C15)); if (val > m) m = val; }
 *   return m;
 * Lift target: vm_smax64_loop_target.
 *
 * Distinct from vm_minarray_loop (i32 min via comparison reduction):
 * exercises i64 signed-max via icmp sgt + conditional assignment.  The
 * golden-ratio multiplier produces input-dependent values that span
 * positive and negative i64 ranges across iterations.
 */
#include <stdio.h>
#include <stdint.h>

enum SmVmPc {
    SM_LOAD       = 0,
    SM_INIT       = 1,
    SM_LOOP_CHECK = 2,
    SM_LOOP_BODY  = 3,
    SM_LOOP_INC   = 4,
    SM_HALT       = 5,
};

__declspec(noinline)
int64_t vm_smax64_loop_target(uint64_t x) {
    int     idx = 0;
    int     n   = 0;
    uint64_t xx = 0;
    int64_t m   = 0;
    int     pc  = SM_LOAD;

    while (1) {
        if (pc == SM_LOAD) {
            n  = (int)(x & 0x1Full) + 1;
            xx = x;
            m  = (int64_t)0x8000000000000000ll;  /* INT64_MIN */
            pc = SM_INIT;
        } else if (pc == SM_INIT) {
            idx = 0;
            pc = SM_LOOP_CHECK;
        } else if (pc == SM_LOOP_CHECK) {
            pc = (idx < n) ? SM_LOOP_BODY : SM_HALT;
        } else if (pc == SM_LOOP_BODY) {
            int64_t val = (int64_t)(xx ^ ((uint64_t)idx * 0x9E3779B97F4A7C15ull));
            if (val > m) {
                m = val;
            }
            pc = SM_LOOP_INC;
        } else if (pc == SM_LOOP_INC) {
            idx = idx + 1;
            pc = SM_LOOP_CHECK;
        } else if (pc == SM_HALT) {
            return m;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_smax64(0xCAFE)=%lld vm_smax64(0xCAFEBABE)=%lld\n",
           (long long)vm_smax64_loop_target(0xCAFEull),
           (long long)vm_smax64_loop_target(0xCAFEBABEull));
    return 0;
}
```
