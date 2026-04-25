# vm_tribonacci64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_tribonacci64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_tribonacci64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_tribonacci64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_tribonacci64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_tribonacci64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 3405691581 | 3405691581 | — | **no** | x=0, n=1: a+b+c = 0+max+0xCAFEBABE |
| 2 | RCX=1 | 6811383163 | 6811383163 | — | **no** | x=1, n=2 |
| 3 | RCX=5 | 81736597841 | 81736597841 | — | **no** | x=5, n=6 |
| 4 | RCX=15 | 36130981799577 | 36130981799577 | — | **no** | x=15, n=16 max |
| 5 | RCX=255 | 36130979858729 | 36130979858729 | — | **no** | x=0xFF, n=16 |
| 6 | RCX=51966 | 19643830442345 | 19643830442345 | — | **no** | x=0xCAFE, n=15 |
| 7 | RCX=3405691582 | 18446738267005399465 | 18446738267005399465 | — | **no** | x=0xCAFEBABE: c-init = 0 (xor self) |
| 8 | RCX=1311768467463790320 | 1311768466214249549 | 1311768466214249549 | — | **no** | x=0x123...DEF0, n=1 |
| 9 | RCX=18446744073709551615 | 18446707942727541801 | 18446707942727541801 | — | **no** | max u64, n=16 |
| 10 | RCX=11400714819323198485 | 9344711213309311841 | 9344711213309311841 | — | **no** | x=K (golden ratio), n=6 |

## Failure detail

### case 1: x=0, n=1: a+b+c = 0+max+0xCAFEBABE

- inputs: `RCX=0`
- manifest expected: `3405691581`
- native: `3405691581`
- lifted: `—`

### case 2: x=1, n=2

- inputs: `RCX=1`
- manifest expected: `6811383163`
- native: `6811383163`
- lifted: `—`

### case 3: x=5, n=6

- inputs: `RCX=5`
- manifest expected: `81736597841`
- native: `81736597841`
- lifted: `—`

### case 4: x=15, n=16 max

- inputs: `RCX=15`
- manifest expected: `36130981799577`
- native: `36130981799577`
- lifted: `—`

### case 5: x=0xFF, n=16

- inputs: `RCX=255`
- manifest expected: `36130979858729`
- native: `36130979858729`
- lifted: `—`

### case 6: x=0xCAFE, n=15

- inputs: `RCX=51966`
- manifest expected: `19643830442345`
- native: `19643830442345`
- lifted: `—`

### case 7: x=0xCAFEBABE: c-init = 0 (xor self)

- inputs: `RCX=3405691582`
- manifest expected: `18446738267005399465`
- native: `18446738267005399465`
- lifted: `—`

### case 8: x=0x123...DEF0, n=1

- inputs: `RCX=1311768467463790320`
- manifest expected: `1311768466214249549`
- native: `1311768466214249549`
- lifted: `—`

### case 9: max u64, n=16

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446707942727541801`
- native: `18446707942727541801`
- lifted: `—`

### case 10: x=K (golden ratio), n=6

- inputs: `RCX=11400714819323198485`
- manifest expected: `9344711213309311841`
- native: `9344711213309311841`
- lifted: `—`

## Source

```c
/* PC-state VM running a three-state Tribonacci-like recurrence on full
 * uint64_t.
 *   a = x;  b = ~x;  c = x ^ 0xCAFEBABE;
 *   for i in 0..n: { t = a + b + c; a = b; b = c; c = t; }
 *   return c;
 * Variable trip n = (x & 0xF) + 1.
 * Lift target: vm_tribonacci64_loop_target.
 *
 * Distinct from vm_fibonacci64_loop (two-state phi): exercises a
 * three-state phi chain on full i64 with three rolling slots advancing
 * one position per iteration.  Each new c uses all three previous
 * states; previous TEA-class compound cross-update failed but this
 * single-direction shift is the same shape as Fibonacci, just wider.
 */
#include <stdio.h>
#include <stdint.h>

enum TbVmPc {
    TB_LOAD       = 0,
    TB_INIT       = 1,
    TB_LOOP_CHECK = 2,
    TB_LOOP_BODY  = 3,
    TB_LOOP_INC   = 4,
    TB_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_tribonacci64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t a   = 0;
    uint64_t b   = 0;
    uint64_t c   = 0;
    uint64_t t   = 0;
    int      pc  = TB_LOAD;

    while (1) {
        if (pc == TB_LOAD) {
            n = (int)(x & 0xFull) + 1;
            a = x;
            b = ~x;
            c = x ^ 0xCAFEBABEull;
            pc = TB_INIT;
        } else if (pc == TB_INIT) {
            idx = 0;
            pc = TB_LOOP_CHECK;
        } else if (pc == TB_LOOP_CHECK) {
            pc = (idx < n) ? TB_LOOP_BODY : TB_HALT;
        } else if (pc == TB_LOOP_BODY) {
            t = a + b + c;
            a = b;
            b = c;
            c = t;
            pc = TB_LOOP_INC;
        } else if (pc == TB_LOOP_INC) {
            idx = idx + 1;
            pc = TB_LOOP_CHECK;
        } else if (pc == TB_HALT) {
            return c;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_tribonacci64(0xCAFE)=%llu vm_tribonacci64(0xFF)=%llu\n",
           (unsigned long long)vm_tribonacci64_loop_target(0xCAFEull),
           (unsigned long long)vm_tribonacci64_loop_target(0xFFull));
    return 0;
}
```
