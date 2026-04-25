# vm_nested64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_nested64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_nested64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_nested64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_nested64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_nested64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0, a=1,b=1,s=0 |
| 2 | RCX=1 | 962 | 962 | — | **no** | x=1, a=2,b=1 |
| 3 | RCX=7 | 5971184918795 | 5971184918795 | — | **no** | x=7, a=8,b=1 |
| 4 | RCX=255 | 10894761712370600223 | 10894761712370600223 | — | **no** | x=0xFF, a=8,b=8 (max 64) |
| 5 | RCX=51966 | 10483213562186932506 | 10483213562186932506 | — | **no** | x=0xCAFE, a=7,b=8 (56 iters) |
| 6 | RCX=3405691582 | 17568069125822042330 | 17568069125822042330 | — | **no** | 0xCAFEBABE, a=7,b=8 |
| 7 | RCX=1311768467463790320 | 81985057741989747 | 81985057741989747 | — | **no** | 0x123...DEF0, a=1,b=7 |
| 8 | RCX=18446744073709551615 | 5597661801495414815 | 5597661801495414815 | — | **no** | max u64, a=8,b=8 |
| 9 | RCX=11400714819323198485 | 12085406143598956766 | 12085406143598956766 | — | **no** | K (golden), a=6,b=3 (18 iters) |
| 10 | RCX=127 | 17469583793787783327 | 17469583793787783327 | — | **no** | x=0x7F, a=8,b=8 |

## Failure detail

### case 1: x=0, a=1,b=1,s=0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1, a=2,b=1

- inputs: `RCX=1`
- manifest expected: `962`
- native: `962`
- lifted: `—`

### case 3: x=7, a=8,b=1

- inputs: `RCX=7`
- manifest expected: `5971184918795`
- native: `5971184918795`
- lifted: `—`

### case 4: x=0xFF, a=8,b=8 (max 64)

- inputs: `RCX=255`
- manifest expected: `10894761712370600223`
- native: `10894761712370600223`
- lifted: `—`

### case 5: x=0xCAFE, a=7,b=8 (56 iters)

- inputs: `RCX=51966`
- manifest expected: `10483213562186932506`
- native: `10483213562186932506`
- lifted: `—`

### case 6: 0xCAFEBABE, a=7,b=8

- inputs: `RCX=3405691582`
- manifest expected: `17568069125822042330`
- native: `17568069125822042330`
- lifted: `—`

### case 7: 0x123...DEF0, a=1,b=7

- inputs: `RCX=1311768467463790320`
- manifest expected: `81985057741989747`
- native: `81985057741989747`
- lifted: `—`

### case 8: max u64, a=8,b=8

- inputs: `RCX=18446744073709551615`
- manifest expected: `5597661801495414815`
- native: `5597661801495414815`
- lifted: `—`

### case 9: K (golden), a=6,b=3 (18 iters)

- inputs: `RCX=11400714819323198485`
- manifest expected: `12085406143598956766`
- native: `12085406143598956766`
- lifted: `—`

### case 10: x=0x7F, a=8,b=8

- inputs: `RCX=127`
- manifest expected: `17469583793787783327`
- native: `17469583793787783327`
- lifted: `—`

## Source

```c
/* PC-state VM with a doubly-nested loop on full uint64_t state.  Both
 * outer and inner bounds derive from the input.
 *   a = (x & 7) + 1;            // outer trip 1..8
 *   b = ((x >> 3) & 7) + 1;     // inner trip 1..8
 *   s = x;
 *   for i in 0..a:
 *     for j in 0..b:
 *       s = s * 31 + (i*b + j);
 *   return s;
 * Total inner iterations 1..64.  Lift target: vm_nested64_loop_target.
 *
 * Distinct from vm_nested_loop (i32 state, simpler body): exercises a
 * full i64 mul-add recurrence inside doubly-nested PC-state loops with
 * both bounds symbolic.
 */
#include <stdio.h>
#include <stdint.h>

enum NsVmPc {
    NS_LOAD       = 0,
    NS_INIT_OUTER = 1,
    NS_OUTER_CHK  = 2,
    NS_INIT_INNER = 3,
    NS_INNER_CHK  = 4,
    NS_BODY       = 5,
    NS_INNER_INC  = 6,
    NS_OUTER_INC  = 7,
    NS_HALT       = 8,
};

__declspec(noinline)
uint64_t vm_nested64_loop_target(uint64_t x) {
    int      a = 0;
    int      b = 0;
    int      i = 0;
    int      j = 0;
    uint64_t s = 0;
    int      pc = NS_LOAD;

    while (1) {
        if (pc == NS_LOAD) {
            a = (int)(x & 7ull) + 1;
            b = (int)((x >> 3) & 7ull) + 1;
            s = x;
            pc = NS_INIT_OUTER;
        } else if (pc == NS_INIT_OUTER) {
            i = 0;
            pc = NS_OUTER_CHK;
        } else if (pc == NS_OUTER_CHK) {
            pc = (i < a) ? NS_INIT_INNER : NS_HALT;
        } else if (pc == NS_INIT_INNER) {
            j = 0;
            pc = NS_INNER_CHK;
        } else if (pc == NS_INNER_CHK) {
            pc = (j < b) ? NS_BODY : NS_OUTER_INC;
        } else if (pc == NS_BODY) {
            s = s * 31ull + (uint64_t)(i * b + j);
            pc = NS_INNER_INC;
        } else if (pc == NS_INNER_INC) {
            j = j + 1;
            pc = NS_INNER_CHK;
        } else if (pc == NS_OUTER_INC) {
            i = i + 1;
            pc = NS_OUTER_CHK;
        } else if (pc == NS_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_nested64(0xFF)=%llu vm_nested64(0xCAFE)=%llu\n",
           (unsigned long long)vm_nested64_loop_target(0xFFull),
           (unsigned long long)vm_nested64_loop_target(0xCAFEull));
    return 0;
}
```
