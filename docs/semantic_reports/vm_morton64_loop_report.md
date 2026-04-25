# vm_morton64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_morton64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_morton64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_morton64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_morton64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_morton64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | x=0 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1: bit 0 stays at 0 |
| 3 | RCX=2 | 4 | 4 | — | **no** | x=2: bit 1 -> bit 2 |
| 4 | RCX=3 | 5 | 5 | — | **no** | x=3 = bit 0 + bit 1 -> 1+4 = 5 |
| 5 | RCX=255 | 21845 | 21845 | — | **no** | x=0xFF -> 0x5555 |
| 6 | RCX=4294967295 | 6148914691236517205 | 6148914691236517205 | — | **no** | x=0xFFFFFFFF -> 0x5555555555555555 alternating |
| 7 | RCX=51966 | 1346655572 | 1346655572 | — | **no** | x=0xCAFE -> 0x50445554 |
| 8 | RCX=3405691582 | 5783841641878275412 | 5783841641878275412 | — | **no** | 0xCAFEBABE |
| 9 | RCX=2863311530 | 4919131752989213764 | 4919131752989213764 | — | **no** | 0xAAAAAAAA -> 0x4444444444444444 |
| 10 | RCX=1431655765 | 1229782938247303441 | 1229782938247303441 | — | **no** | 0x55555555 -> 0x1111111111111111 |

## Failure detail

### case 1: x=0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1: bit 0 stays at 0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=2: bit 1 -> bit 2

- inputs: `RCX=2`
- manifest expected: `4`
- native: `4`
- lifted: `—`

### case 4: x=3 = bit 0 + bit 1 -> 1+4 = 5

- inputs: `RCX=3`
- manifest expected: `5`
- native: `5`
- lifted: `—`

### case 5: x=0xFF -> 0x5555

- inputs: `RCX=255`
- manifest expected: `21845`
- native: `21845`
- lifted: `—`

### case 6: x=0xFFFFFFFF -> 0x5555555555555555 alternating

- inputs: `RCX=4294967295`
- manifest expected: `6148914691236517205`
- native: `6148914691236517205`
- lifted: `—`

### case 7: x=0xCAFE -> 0x50445554

- inputs: `RCX=51966`
- manifest expected: `1346655572`
- native: `1346655572`
- lifted: `—`

### case 8: 0xCAFEBABE

- inputs: `RCX=3405691582`
- manifest expected: `5783841641878275412`
- native: `5783841641878275412`
- lifted: `—`

### case 9: 0xAAAAAAAA -> 0x4444444444444444

- inputs: `RCX=2863311530`
- manifest expected: `4919131752989213764`
- native: `4919131752989213764`
- lifted: `—`

### case 10: 0x55555555 -> 0x1111111111111111

- inputs: `RCX=1431655765`
- manifest expected: `1229782938247303441`
- native: `1229782938247303441`
- lifted: `—`

## Source

```c
/* PC-state VM running an i64 Morton (Z-order) bit-spread of low 32 bits
 * to 64 bits.  For each of 32 input bits, place bit i of input at bit
 * position 2*i of output (leaving 2*i+1 as zero).  32-trip fixed loop.
 *   result = 0;
 *   for i in 0..32:
 *     bit = (state >> i) & 1
 *     result |= bit << (2*i)
 *   return result;
 * Lift target: vm_morton64_loop_target.
 *
 * Distinct from vm_bswap64_loop (whole-byte permute) and
 * vm_nibrev64_loop (whole-nibble permute): exercises a 1-bit-stride
 * fan-out where each bit is placed at a different even position.  The
 * lifter likely cannot recognize this as any LLVM intrinsic.
 */
#include <stdio.h>
#include <stdint.h>

enum MoVmPc {
    MO_LOAD       = 0,
    MO_INIT       = 1,
    MO_LOOP_CHECK = 2,
    MO_LOOP_BODY  = 3,
    MO_LOOP_INC   = 4,
    MO_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_morton64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t state  = 0;
    uint64_t result = 0;
    int      pc     = MO_LOAD;

    while (1) {
        if (pc == MO_LOAD) {
            state  = x & 0xFFFFFFFFull;
            result = 0ull;
            pc = MO_INIT;
        } else if (pc == MO_INIT) {
            idx = 0;
            pc = MO_LOOP_CHECK;
        } else if (pc == MO_LOOP_CHECK) {
            pc = (idx < 32) ? MO_LOOP_BODY : MO_HALT;
        } else if (pc == MO_LOOP_BODY) {
            uint64_t bit = (state >> idx) & 1ull;
            result = result | (bit << (2 * idx));
            pc = MO_LOOP_INC;
        } else if (pc == MO_LOOP_INC) {
            idx = idx + 1;
            pc = MO_LOOP_CHECK;
        } else if (pc == MO_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_morton64(0xFFFFFFFF)=%llu vm_morton64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_morton64_loop_target(0xFFFFFFFFull),
           (unsigned long long)vm_morton64_loop_target(0xCAFEBABEull));
    return 0;
}
```
