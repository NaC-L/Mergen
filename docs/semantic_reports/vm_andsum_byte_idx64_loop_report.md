# vm_andsum_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_andsum_byte_idx64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_andsum_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_andsum_byte_idx64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_andsum_byte_idx64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_andsum_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1 n=2: (1 & 1) + (0 & 2)=1 |
| 3 | RCX=2 | 0 | 0 | — | **no** | x=2 n=3: (2 & 1)=0 + (0 & 2)=0 + (0 & 3)=0 |
| 4 | RCX=7 | 1 | 1 | — | **no** | x=7 n=8: only byte0=7 -> 7 & 1 = 1 |
| 5 | RCX=8 | 0 | 0 | — | **no** | x=8 n=1: 8 & 1=0 |
| 6 | RCX=3405691582 | 4 | 4 | — | **no** | 0xCAFEBABE: n=7 sum of byte&counter |
| 7 | RCX=3735928559 | 8 | 8 | — | **no** | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 36 | 36 | — | **no** | all 0xFF n=8: sum 1..8=36 (counter low bits all kept) |
| 9 | RCX=72623859790382856 | 0 | 0 | — | **no** | 0x0102...0708: n=1 byte0=8 & 1=0 |
| 10 | RCX=1311768467463790320 | 0 | 0 | — | **no** | 0x12345...EF0: n=1 byte0=0xF0 & 1=0 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: (1 & 1) + (0 & 2)=1

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2 n=3: (2 & 1)=0 + (0 & 2)=0 + (0 & 3)=0

- inputs: `RCX=2`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7 -> 7 & 1 = 1

- inputs: `RCX=7`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 5: x=8 n=1: 8 & 1=0

- inputs: `RCX=8`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 sum of byte&counter

- inputs: `RCX=3405691582`
- manifest expected: `4`
- native: `4`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8

- inputs: `RCX=3735928559`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 8: all 0xFF n=8: sum 1..8=36 (counter low bits all kept)

- inputs: `RCX=18446744073709551615`
- manifest expected: `36`
- native: `36`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8 & 1=0

- inputs: `RCX=72623859790382856`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 10: 0x12345...EF0: n=1 byte0=0xF0 & 1=0

- inputs: `RCX=1311768467463790320`
- manifest expected: `0`
- native: `0`
- lifted: `—`

## Source

```c
/* PC-state VM that ANDs each byte with the loop index and sums:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFF) & (i + 1));   // byte AND counter, ADD-folded
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_andsum_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_byte_idx64_loop  (byte * counter, ADD)
 *   - vm_xormul_byte_idx64_loop   (byte * counter, XOR)
 *   - vm_notand_chain64_loop      (NOT-AND of state, no counter)
 *
 * Tests `and i64 byte, counter` (AND of zext-byte with phi-tracked
 * counter (i+1)) folded via ADD.  Counter values 1..8 are <128 so
 * the AND keeps only low bits of each byte.  All-0xFF input
 * accumulates 1+2+3+...+8 = 36.
 */
#include <stdio.h>
#include <stdint.h>

enum AsVmPc {
    AS_INIT_ALL = 0,
    AS_CHECK    = 1,
    AS_BODY     = 2,
    AS_INC      = 3,
    AS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_andsum_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = AS_INIT_ALL;

    while (1) {
        if (pc == AS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = AS_CHECK;
        } else if (pc == AS_CHECK) {
            pc = (i < n) ? AS_BODY : AS_HALT;
        } else if (pc == AS_BODY) {
            r = r + ((s & 0xFFull) & (i + 1ull));
            s = s >> 8;
            pc = AS_INC;
        } else if (pc == AS_INC) {
            i = i + 1ull;
            pc = AS_CHECK;
        } else if (pc == AS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_andsum_byte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_andsum_byte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
