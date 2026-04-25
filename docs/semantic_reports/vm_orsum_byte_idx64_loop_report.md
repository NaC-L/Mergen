# vm_orsum_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_orsum_byte_idx64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_orsum_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_orsum_byte_idx64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_orsum_byte_idx64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_orsum_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | — | **no** | x=0 n=1: 0\|0\|1=1 |
| 2 | RCX=1 | 3 | 3 | — | **no** | x=1 n=2: 0\|1\|1=1; \|0\|2=3 |
| 3 | RCX=2 | 3 | 3 | — | **no** | x=2 n=3: bytes [2,0,0] \| counters [1,2,3] |
| 4 | RCX=7 | 15 | 15 | — | **no** | x=7 n=8: 7 \| (1\|2\|...\|8) = 7\|15 = 15 |
| 5 | RCX=8 | 9 | 9 | — | **no** | x=8 n=1: 8\|1=9 |
| 6 | RCX=3405691582 | 255 | 255 | — | **no** | 0xCAFEBABE: n=7 OR of high-byte BE=0xBE \| counters fills low 8 bits |
| 7 | RCX=3735928559 | 255 | 255 | — | **no** | 0xDEADBEEF: n=8 fills low 8 bits |
| 8 | RCX=18446744073709551615 | 255 | 255 | — | **no** | all 0xFF: low byte already 0xFF -> 0xFF |
| 9 | RCX=72623859790382856 | 9 | 9 | — | **no** | 0x0102...0708: n=1 byte0=8 \| 1=9 |
| 10 | RCX=1311768467463790320 | 241 | 241 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 \| 1=0xF1=241 |

## Failure detail

### case 1: x=0 n=1: 0|0|1=1

- inputs: `RCX=0`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 2: x=1 n=2: 0|1|1=1; |0|2=3

- inputs: `RCX=1`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 3: x=2 n=3: bytes [2,0,0] | counters [1,2,3]

- inputs: `RCX=2`
- manifest expected: `3`
- native: `3`
- lifted: `—`

### case 4: x=7 n=8: 7 | (1|2|...|8) = 7|15 = 15

- inputs: `RCX=7`
- manifest expected: `15`
- native: `15`
- lifted: `—`

### case 5: x=8 n=1: 8|1=9

- inputs: `RCX=8`
- manifest expected: `9`
- native: `9`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 OR of high-byte BE=0xBE | counters fills low 8 bits

- inputs: `RCX=3405691582`
- manifest expected: `255`
- native: `255`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8 fills low 8 bits

- inputs: `RCX=3735928559`
- manifest expected: `255`
- native: `255`
- lifted: `—`

### case 8: all 0xFF: low byte already 0xFF -> 0xFF

- inputs: `RCX=18446744073709551615`
- manifest expected: `255`
- native: `255`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 | 1=9

- inputs: `RCX=72623859790382856`
- manifest expected: `9`
- native: `9`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=0xF0 | 1=0xF1=241

- inputs: `RCX=1311768467463790320`
- manifest expected: `241`
- native: `241`
- lifted: `—`

## Source

```c
/* PC-state VM that ORs bytes and counter values into a single
 * accumulator over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r | ((s & 0xFF) | (i + 1));   // OR-accumulator
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_orsum_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (XOR fold of byte * counter)
 *   - vm_andsum_byte_idx64_loop  (AND of byte with counter, ADD-folded)
 *   - vm_uintadd_byte_idx64_loop (ADD of byte * counter)
 *
 * Tests `or i64` of zext-byte with phi-tracked counter (i+1) folded
 * via OR-accumulator.  Unlike XOR which can cancel, OR is monotone
 * (only sets bits).  Counter values 1..8 contribute fixed low bits
 * regardless of byte content.
 */
#include <stdio.h>
#include <stdint.h>

enum OsVmPc {
    OS_INIT_ALL = 0,
    OS_CHECK    = 1,
    OS_BODY     = 2,
    OS_INC      = 3,
    OS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orsum_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = OS_INIT_ALL;

    while (1) {
        if (pc == OS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = OS_CHECK;
        } else if (pc == OS_CHECK) {
            pc = (i < n) ? OS_BODY : OS_HALT;
        } else if (pc == OS_BODY) {
            r = r | ((s & 0xFFull) | (i + 1ull));
            s = s >> 8;
            pc = OS_INC;
        } else if (pc == OS_INC) {
            i = i + 1ull;
            pc = OS_CHECK;
        } else if (pc == OS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orsum_byte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_orsum_byte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
