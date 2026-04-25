# vm_4state64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_4state64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_4state64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_4state64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_4state64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_4state64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 7581304714302077699 | 7581304714302077699 | — | **no** | x=0, n=1 |
| 2 | RCX=1 | 15162609428604155393 | 15162609428604155393 | — | **no** | x=1, n=2 |
| 3 | RCX=5 | 6135728040287875135 | 6135728040287875135 | — | **no** | x=5, n=6 |
| 4 | RCX=15 | 406151117814638971 | 406151117814638971 | — | **no** | x=15, n=16 max |
| 5 | RCX=255 | 406151117813620251 | 406151117813620251 | — | **no** | x=0xFF, n=16 |
| 6 | RCX=51966 | 12054802488707175559 | 12054802488707175559 | — | **no** | 0xCAFE, n=15 |
| 7 | RCX=3405691582 | 12054768846522478919 | 12054768846522478919 | — | **no** | 0xCAFEBABE, n=15 |
| 8 | RCX=1311768467463790320 | 7263774620141486851 | 7263774620141486851 | — | **no** | 0x123...DEF0, n=1 |
| 9 | RCX=18446744073709551615 | 18040592955894579739 | 18040592955894579739 | — | **no** | max u64, n=16 |
| 10 | RCX=11400714819323198485 | 18414027014724759455 | 18414027014724759455 | — | **no** | K (golden), n=6 |

## Failure detail

### case 1: x=0, n=1

- inputs: `RCX=0`
- manifest expected: `7581304714302077699`
- native: `7581304714302077699`
- lifted: `—`

### case 2: x=1, n=2

- inputs: `RCX=1`
- manifest expected: `15162609428604155393`
- native: `15162609428604155393`
- lifted: `—`

### case 3: x=5, n=6

- inputs: `RCX=5`
- manifest expected: `6135728040287875135`
- native: `6135728040287875135`
- lifted: `—`

### case 4: x=15, n=16 max

- inputs: `RCX=15`
- manifest expected: `406151117814638971`
- native: `406151117814638971`
- lifted: `—`

### case 5: x=0xFF, n=16

- inputs: `RCX=255`
- manifest expected: `406151117813620251`
- native: `406151117813620251`
- lifted: `—`

### case 6: 0xCAFE, n=15

- inputs: `RCX=51966`
- manifest expected: `12054802488707175559`
- native: `12054802488707175559`
- lifted: `—`

### case 7: 0xCAFEBABE, n=15

- inputs: `RCX=3405691582`
- manifest expected: `12054768846522478919`
- native: `12054768846522478919`
- lifted: `—`

### case 8: 0x123...DEF0, n=1

- inputs: `RCX=1311768467463790320`
- manifest expected: `7263774620141486851`
- native: `7263774620141486851`
- lifted: `—`

### case 9: max u64, n=16

- inputs: `RCX=18446744073709551615`
- manifest expected: `18040592955894579739`
- native: `18040592955894579739`
- lifted: `—`

### case 10: K (golden), n=6

- inputs: `RCX=11400714819323198485`
- manifest expected: `18414027014724759455`
- native: `18414027014724759455`
- lifted: `—`

## Source

```c
/* PC-state VM running a four-state phi chain on full uint64_t.
 *   a = x;  b = ~x;  c = x ^ K1;  d = x ^ K2;
 *   for i in 0..n: { t = a + b + c + d; a = b; b = c; c = d; d = t; }
 *   return d;
 * Variable trip n = (x & 0xF) + 1.
 * Lift target: vm_4state64_loop_target.
 *
 * Distinct from vm_fibonacci64_loop (2 states) and vm_tribonacci64_loop
 * (3 states): exercises a 4-state direct-shift phi chain on full i64.
 * Each new t reads ALL four previous values; only single-direction
 * shift (a<-b<-c<-d<-t) so no compound cross-update issue.
 */
#include <stdio.h>
#include <stdint.h>

enum F4VmPc {
    F4_LOAD       = 0,
    F4_INIT       = 1,
    F4_LOOP_CHECK = 2,
    F4_LOOP_BODY  = 3,
    F4_LOOP_INC   = 4,
    F4_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_4state64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t a   = 0;
    uint64_t b   = 0;
    uint64_t c   = 0;
    uint64_t d   = 0;
    uint64_t t   = 0;
    int      pc  = F4_LOAD;

    while (1) {
        if (pc == F4_LOAD) {
            n = (int)(x & 0xFull) + 1;
            a = x;
            b = ~x;
            c = x ^ 0xCAFEBABEDEADBEEFull;
            d = x ^ 0x9E3779B97F4A7C15ull;
            pc = F4_INIT;
        } else if (pc == F4_INIT) {
            idx = 0;
            pc = F4_LOOP_CHECK;
        } else if (pc == F4_LOOP_CHECK) {
            pc = (idx < n) ? F4_LOOP_BODY : F4_HALT;
        } else if (pc == F4_LOOP_BODY) {
            t = a + b + c + d;
            a = b;
            b = c;
            c = d;
            d = t;
            pc = F4_LOOP_INC;
        } else if (pc == F4_LOOP_INC) {
            idx = idx + 1;
            pc = F4_LOOP_CHECK;
        } else if (pc == F4_HALT) {
            return d;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_4state64(0xCAFE)=%llu vm_4state64(0xFF)=%llu\n",
           (unsigned long long)vm_4state64_loop_target(0xCAFEull),
           (unsigned long long)vm_4state64_loop_target(0xFFull));
    return 0;
}
```
