# vm_condsum64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_condsum64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_condsum64_loop.ll`
- **Symbol:** `vm_condsum64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_condsum64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_condsum64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_condsum64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0, n=1: val=0 even, no accumulate |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1, n=2 |
| 3 | RCX=2 | 11400714819323198487 | 11400714819323198487 | — | **no** | x=2, n=3 |
| 4 | RCX=31 | 6053433728553997728 | 6053433728553997728 | — | **no** | x=0x1F, n=32 max |
| 5 | RCX=255 | 6053433728554001312 | 6053433728554001312 | — | **no** | x=0xFF, n=32 |
| 6 | RCX=51966 | 1063408102092763991 | 1063408102092763991 | — | **no** | 0xCAFE, n=31 |
| 7 | RCX=3405691582 | 1063408153177358231 | 1063408153177358231 | — | **no** | 0xCAFEBABE, n=31 |
| 8 | RCX=1311768467463790320 | 2270133228012960960 | 2270133228012960960 | — | **no** | 0x123...DEF0, n=17 |
| 9 | RCX=18446744073709551615 | 6053433728553997216 | 6053433728553997216 | — | **no** | max u64, n=32 |
| 10 | RCX=11400714819323198485 | 14427431683600197101 | 14427431683600197101 | — | **no** | K (golden), n=22 |

## Failure detail

### case 1: x=0, n=1: val=0 even, no accumulate

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1, n=2

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2, n=3

- inputs: `RCX=2`
- manifest expected: `11400714819323198487`
- native: `11400714819323198487`
- lifted: `—`

### case 4: x=0x1F, n=32 max

- inputs: `RCX=31`
- manifest expected: `6053433728553997728`
- native: `6053433728553997728`
- lifted: `—`

### case 5: x=0xFF, n=32

- inputs: `RCX=255`
- manifest expected: `6053433728554001312`
- native: `6053433728554001312`
- lifted: `—`

### case 6: 0xCAFE, n=31

- inputs: `RCX=51966`
- manifest expected: `1063408102092763991`
- native: `1063408102092763991`
- lifted: `—`

### case 7: 0xCAFEBABE, n=31

- inputs: `RCX=3405691582`
- manifest expected: `1063408153177358231`
- native: `1063408153177358231`
- lifted: `—`

### case 8: 0x123...DEF0, n=17

- inputs: `RCX=1311768467463790320`
- manifest expected: `2270133228012960960`
- native: `2270133228012960960`
- lifted: `—`

### case 9: max u64, n=32

- inputs: `RCX=18446744073709551615`
- manifest expected: `6053433728553997216`
- native: `6053433728553997216`
- lifted: `—`

### case 10: K (golden), n=22

- inputs: `RCX=11400714819323198485`
- manifest expected: `14427431683600197101`
- native: `14427431683600197101`
- lifted: `—`

## Source

```c
/* PC-state VM that conditionally sums values (only when the value is
 * odd) over a derived sequence.
 *   s = 0; n = (x & 0x1F) + 1;
 *   for i in 0..n:
 *     val = x + i * K_golden
 *     if (val & 1) s = s + val
 *   return s;
 * Lift target: vm_condsum64_loop_target.
 *
 * Distinct from vm_smax64_loop (always-update via icmp sgt) and
 * vm_satadd64_loop (overflow-clamp): the body GATES the accumulator
 * on a parity bit-test, so some iterations contribute zero.
 */
#include <stdio.h>
#include <stdint.h>

enum CsVmPc {
    CS_LOAD       = 0,
    CS_INIT       = 1,
    CS_LOOP_CHECK = 2,
    CS_LOOP_BODY  = 3,
    CS_LOOP_INC   = 4,
    CS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_condsum64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t s   = 0;
    int      pc  = CS_LOAD;

    while (1) {
        if (pc == CS_LOAD) {
            xx = x;
            n  = (int)(x & 0x1Full) + 1;
            s  = 0ull;
            pc = CS_INIT;
        } else if (pc == CS_INIT) {
            idx = 0;
            pc = CS_LOOP_CHECK;
        } else if (pc == CS_LOOP_CHECK) {
            pc = (idx < n) ? CS_LOOP_BODY : CS_HALT;
        } else if (pc == CS_LOOP_BODY) {
            uint64_t val = xx + (uint64_t)idx * 0x9E3779B97F4A7C15ull;
            if ((val & 1ull) != 0ull) {
                s = s + val;
            }
            pc = CS_LOOP_INC;
        } else if (pc == CS_LOOP_INC) {
            idx = idx + 1;
            pc = CS_LOOP_CHECK;
        } else if (pc == CS_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_condsum64(0xCAFE)=%llu vm_condsum64(0xFF)=%llu\n",
           (unsigned long long)vm_condsum64_loop_target(0xCAFEull),
           (unsigned long long)vm_condsum64_loop_target(0xFFull));
    return 0;
}
```
