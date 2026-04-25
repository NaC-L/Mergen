# vm_byteprod64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byteprod64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_byteprod64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byteprod64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_byteprod64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byteprod64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0 n=1: 1*0=0 |
| 2 | RCX=1 | 0 | 0 | — | **no** | x=1 n=2: 1*1=1; 1*0=0 |
| 3 | RCX=2 | 0 | 0 | — | **no** | x=2 n=3: byte0=2 then 0,0 -> 0 |
| 4 | RCX=7 | 0 | 0 | — | **no** | x=7 n=8: only byte0=7 nonzero, then 0 |
| 5 | RCX=8 | 8 | 8 | — | **no** | x=8 n=1: 1*8=8 (no zero byte to wreck) |
| 6 | RCX=3405691582 | 0 | 0 | — | **no** | 0xCAFEBABE: n=7 high bytes are 0 |
| 7 | RCX=3735928559 | 0 | 0 | — | **no** | 0xDEADBEEF: n=8 high bytes are 0 |
| 8 | RCX=18446744073709551615 | 17878103347812890625 | 17878103347812890625 | — | **no** | all 0xFF: 0xFF^8 mod 2^64 |
| 9 | RCX=72623859790382856 | 8 | 8 | — | **no** | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=144965140780024580 | 1512 | 1512 | — | **no** | 0x0203...0304: n=5 -> 4*3*2*9*7=1512 |

## Failure detail

### case 1: x=0 n=1: 1*0=0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 1*1=1; 1*0=0

- inputs: `RCX=1`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 3: x=2 n=3: byte0=2 then 0,0 -> 0

- inputs: `RCX=2`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 4: x=7 n=8: only byte0=7 nonzero, then 0

- inputs: `RCX=7`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 5: x=8 n=1: 1*8=8 (no zero byte to wreck)

- inputs: `RCX=8`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 6: 0xCAFEBABE: n=7 high bytes are 0

- inputs: `RCX=3405691582`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 7: 0xDEADBEEF: n=8 high bytes are 0

- inputs: `RCX=3735928559`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 8: all 0xFF: 0xFF^8 mod 2^64

- inputs: `RCX=18446744073709551615`
- manifest expected: `17878103347812890625`
- native: `17878103347812890625`
- lifted: `—`

### case 9: 0x0102...0708: n=1 byte0=8

- inputs: `RCX=72623859790382856`
- manifest expected: `8`
- native: `8`
- lifted: `—`

### case 10: 0x0203...0304: n=5 -> 4*3*2*9*7=1512

- inputs: `RCX=144965140780024580`
- manifest expected: `1512`
- native: `1512`
- lifted: `—`

## Source

```c
/* PC-state VM that computes the running product of bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 1;
 *   for (i = 0; i < n; i++) {
 *     r = r * (s & 0xFF);     // u8 multiplicative chain (mod 2^64)
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byteprod64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesq_sum64_loop          (per-byte squared, ADD-folded)
 *   - vm_xormul_byte_idx64_loop     (byte * counter, XOR-folded)
 *   - vm_uintadd_byte_idx64_loop    (byte * counter, ADD-folded)
 *   - vm_bytesmul_idx64_loop        (signed byte * counter, ADD-folded)
 *
 * Tests `mul i64 r, byte` chained across iterations.  Any zero byte
 * collapses the product to 0 for the rest of the loop, which the
 * lifter must not optimize away (the loop still runs to completion).
 * Inputs with no zero bytes propagate a meaningful product.
 */
#include <stdio.h>
#include <stdint.h>

enum BpVmPc {
    BP_INIT_ALL = 0,
    BP_CHECK    = 1,
    BP_BODY     = 2,
    BP_INC      = 3,
    BP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byteprod64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BP_INIT_ALL;

    while (1) {
        if (pc == BP_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 1ull;
            i = 0ull;
            pc = BP_CHECK;
        } else if (pc == BP_CHECK) {
            pc = (i < n) ? BP_BODY : BP_HALT;
        } else if (pc == BP_BODY) {
            r = r * (s & 0xFFull);
            s = s >> 8;
            pc = BP_INC;
        } else if (pc == BP_INC) {
            i = i + 1ull;
            pc = BP_CHECK;
        } else if (pc == BP_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteprod64(0x0203050709020304)=%llu\n",
           (unsigned long long)vm_byteprod64_loop_target(0x0203050709020304ull));
    return 0;
}
```
