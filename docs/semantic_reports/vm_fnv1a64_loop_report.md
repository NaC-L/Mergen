# vm_fnv1a64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_fnv1a64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_fnv1a64_loop.ll`
- **Symbol:** `vm_fnv1a64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_fnv1a64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_fnv1a64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 12638153115695167455 | 12638153115695167455 | 12638153115695167455 | yes | x=0 n=1: hash of one zero byte |
| 2 | RCX=1 | 589727492704079044 | 589727492704079044 | 589727492704079044 | yes | x=1 n=2: bytes [1,0] |
| 3 | RCX=2 | 16906521902298639629 | 16906521902298639629 | 16906521902298639629 | yes | x=2 n=3 |
| 4 | RCX=7 | 5465015992139406178 | 5465015992139406178 | 5465015992139406178 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 12638161911788193143 | 12638161911788193143 | 12638161911788193143 | yes | x=8 n=1: hash of byte 0x08 |
| 6 | RCX=3405691582 | 4118356257163980823 | 4118356257163980823 | 4118356257163980823 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 8436364122023583835 | 8436364122023583835 | 8436364122023583835 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 10157053723145373757 | 10157053723145373757 | 10157053723145373757 | yes | all 0xFF: 8 bytes of 0xFF |
| 9 | RCX=1311768467463790320 | 12638346629741732591 | 12638346629741732591 | 12638346629741732591 | yes | 0x12345...EF0: n=1 byte 0xF0 |
| 10 | RCX=72623859790382856 | 12638161911788193143 | 12638161911788193143 | 12638161911788193143 | yes | 0x0102...0708: n=1 byte 0x08 (matches x=8) |

## Source

```c
/* PC-state VM running an FNV-1a hash chain over n = (x & 7) + 1 bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xCBF29CE484222325;   // FNV offset basis
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ (s & 0xFF)) * 0x100000001B3ull;   // FNV prime
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_fnv1a64_loop_target.
 *
 * Distinct from:
 *   - vm_djb264_loop      (additive *33 hash, chained add+mul)
 *   - vm_murmurstep64_loop (xor-input then mul-magic then xor-fold; same
 *     input each iter)
 *   - vm_horner64_loop    (polynomial evaluation)
 *
 * Differs from Murmur in two ways: FNV consumes a different byte each
 * iteration (windowed via shift on s) and the loop body is the
 * canonical FNV-1a step xor-then-multiply-by-prime, with no folding
 * shift afterwards.  Tests byte masking, xor-with-state, and i64
 * multiply by a 40-bit prime threaded through a counter-bound loop.
 */
#include <stdio.h>
#include <stdint.h>

enum FvVmPc {
    FV_INIT_ALL = 0,
    FV_CHECK    = 1,
    FV_HASH     = 2,
    FV_SHIFT    = 3,
    FV_INC      = 4,
    FV_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_fnv1a64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = FV_INIT_ALL;

    while (1) {
        if (pc == FV_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xCBF29CE484222325ull;
            i = 0ull;
            pc = FV_CHECK;
        } else if (pc == FV_CHECK) {
            pc = (i < n) ? FV_HASH : FV_HALT;
        } else if (pc == FV_HASH) {
            r = (r ^ (s & 0xFFull)) * 0x100000001B3ull;
            pc = FV_SHIFT;
        } else if (pc == FV_SHIFT) {
            s = s >> 8;
            pc = FV_INC;
        } else if (pc == FV_INC) {
            i = i + 1ull;
            pc = FV_CHECK;
        } else if (pc == FV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fnv1a64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fnv1a64_loop_target(0xCAFEBABEull));
    return 0;
}
```
