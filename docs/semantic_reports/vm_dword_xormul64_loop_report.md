# vm_dword_xormul64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dword_xormul64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_dword_xormul64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dword_xormul64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_dword_xormul64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dword_xormul64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | — | **no** | all zero -> 0 |
| 2 | RCX=1 | 2654435769 | 2654435769 | — | **no** | x=1 n=2: 1*GR^0=GR |
| 3 | RCX=2 | 5308871538 | 5308871538 | — | **no** | x=2 n=1 |
| 4 | RCX=3 | 7963307307 | 7963307307 | — | **no** | x=3 n=2: dword 3 then 0 |
| 5 | RCX=3405691582 | 9040189553442996558 | 9040189553442996558 | — | **no** | 0xCAFEBABE: n=1 single dword |
| 6 | RCX=3735928559 | 9916782397438226871 | 9916782397438226871 | — | **no** | 0xDEADBEEF: n=2 dword + 0 |
| 7 | RCX=18446744073709551615 | 0 | 0 | — | **no** | all 0xFF: 2 XOR of 0xFFFFFFFF*GR cancel |
| 8 | RCX=72623859790382856 | 223718755872922824 | 223718755872922824 | — | **no** | 0x0102...0708: n=1 lower dword=0x05060708 |
| 9 | RCX=1311768467463790320 | 6891098688453380976 | 6891098688453380976 | — | **no** | 0x12345...EF0: n=1 lower dword=0x9ABCDEF0 |
| 10 | RCX=18364758544493064720 | 5269663737911033232 | 5269663737911033232 | — | **no** | 0xFEDCBA9876543210: n=1 lower dword=0x76543210 |

## Failure detail

### case 1: all zero -> 0

- inputs: `RCX=0`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 2: x=1 n=2: 1*GR^0=GR

- inputs: `RCX=1`
- manifest expected: `2654435769`
- native: `2654435769`
- lifted: `—`

### case 3: x=2 n=1

- inputs: `RCX=2`
- manifest expected: `5308871538`
- native: `5308871538`
- lifted: `—`

### case 4: x=3 n=2: dword 3 then 0

- inputs: `RCX=3`
- manifest expected: `7963307307`
- native: `7963307307`
- lifted: `—`

### case 5: 0xCAFEBABE: n=1 single dword

- inputs: `RCX=3405691582`
- manifest expected: `9040189553442996558`
- native: `9040189553442996558`
- lifted: `—`

### case 6: 0xDEADBEEF: n=2 dword + 0

- inputs: `RCX=3735928559`
- manifest expected: `9916782397438226871`
- native: `9916782397438226871`
- lifted: `—`

### case 7: all 0xFF: 2 XOR of 0xFFFFFFFF*GR cancel

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 8: 0x0102...0708: n=1 lower dword=0x05060708

- inputs: `RCX=72623859790382856`
- manifest expected: `223718755872922824`
- native: `223718755872922824`
- lifted: `—`

### case 9: 0x12345...EF0: n=1 lower dword=0x9ABCDEF0

- inputs: `RCX=1311768467463790320`
- manifest expected: `6891098688453380976`
- native: `6891098688453380976`
- lifted: `—`

### case 10: 0xFEDCBA9876543210: n=1 lower dword=0x76543210

- inputs: `RCX=18364758544493064720`
- manifest expected: `5269663737911033232`
- native: `5269663737911033232`
- lifted: `—`

## Source

```c
/* PC-state VM that processes u32 dwords per iteration:
 *
 *   n = (x & 1) + 1;     // 1..2 dword iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     r = r ^ (d * 0x9E3779B9);   // golden-ratio prime mul
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_word_xormul64_loop  (u16 word stride)
 *   - vm_quad_byte_xor64_loop (4 BYTES per iter)
 *   - vm_xormuladd_chain64_loop (xor + mul + add, no stride)
 *
 * Tests u32 zext-i32 reads (mask 0xFFFFFFFF) multiplied by the
 * 32-bit golden-ratio prime 0x9E3779B9 and XOR-folded into the
 * accumulator.  Stride is 32 bits per iter; loop runs 1..2 times.
 */
#include <stdio.h>
#include <stdint.h>

enum DwVmPc {
    DW_INIT_ALL = 0,
    DW_CHECK    = 1,
    DW_BODY     = 2,
    DW_INC      = 3,
    DW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dword_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DW_INIT_ALL;

    while (1) {
        if (pc == DW_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DW_CHECK;
        } else if (pc == DW_CHECK) {
            pc = (i < n) ? DW_BODY : DW_HALT;
        } else if (pc == DW_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = r ^ (d * 0x9E3779B9ull);
            s = s >> 32;
            pc = DW_INC;
        } else if (pc == DW_INC) {
            i = i + 1ull;
            pc = DW_CHECK;
        } else if (pc == DW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_dword_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
```
