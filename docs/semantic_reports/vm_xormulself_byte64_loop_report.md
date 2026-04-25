# vm_xormulself_byte64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xormulself_byte64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_xormulself_byte64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xormulself_byte64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_xormulself_byte64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xormulself_byte64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: 0^(1*1)=1; 1^(0*2)=1 |
| 3 | RCX=2 | 2 | 2 | — | **no** | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | — | **no** | x=7 n=8: only byte0=7 contributes |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1: 0^(8*1)=8 |
| 6 | RCX=3405691582 | 1818216336 | 1818216336 | — | **no** | 0xCAFEBABE: n=7 self-referential cascade |
| 7 | RCX=3735928559 | 1746890527 | 1746890527 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | — | **no** | all 0xFF: cascades but ends at all-1s |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte=8 |
| 10 | RCX=1311768467463790320 | 240 | 240 | — | **no** | 0x12345...EF0: n=1 byte=0xF0 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 0^(1*1)=1; 1^(0*2)=1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3

- inputs: `RCX=2`
- manifest expected: `2`
- native: `2`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7 contributes

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 5: x=8 n=1: 0^(8*1)=8

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 self-referential cascade

- inputs: `RCX=3405691582`
- manifest expected: `1818216336`
- native: `1818216336`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `1746890527`
- native: `1746890527`
- lifted: `—`

### case 8: all 0xFF: cascades but ends at all-1s

- inputs: `RCX=18446744073709551615`
- manifest expected: `18446744073709551615`
- native: `18446744073709551615`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte=8

- inputs: `RCX=72623859790382856`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte=0xF0

- inputs: `RCX=1311768467463790320`
- manifest expected: `240`
- native: `240`
- lifted: `—`

## Source

```c
/* PC-state VM with self-referential multiply per iter:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = r ^ (b * (r + 1));   // r appears in mul operand
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xormulself_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (byte * counter, XOR-folded)
 *   - vm_bytesmul_idx64_loop     (sext byte * counter, ADD)
 *   - vm_squareadd64_loop        (r*r self-multiply on full state)
 *
 * Tests `mul i64 byte, (r+1)` where the multiplier operand is the
 * accumulator+1 (self-reference).  Each iter the byte scales an
 * incremented snapshot of r and XORs back.  Reaches 200-sample
 * milestone.
 */
#include <stdio.h>
#include <stdint.h>

enum XmVmPc {
    XM_INIT_ALL = 0,
    XM_CHECK    = 1,
    XM_BODY     = 2,
    XM_INC      = 3,
    XM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormulself_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XM_INIT_ALL;

    while (1) {
        if (pc == XM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XM_CHECK;
        } else if (pc == XM_CHECK) {
            pc = (i < n) ? XM_BODY : XM_HALT;
        } else if (pc == XM_BODY) {
            uint64_t b = s & 0xFFull;
            r = r ^ (b * (r + 1ull));
            s = s >> 8;
            pc = XM_INC;
        } else if (pc == XM_INC) {
            i = i + 1ull;
            pc = XM_CHECK;
        } else if (pc == XM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormulself_byte64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormulself_byte64_loop_target(0xCAFEBABEull));
    return 0;
}
```
