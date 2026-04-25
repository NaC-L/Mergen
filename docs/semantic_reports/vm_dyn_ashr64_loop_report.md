# vm_dyn_ashr64_loop - original vs lifted equivalence

- **Verdict:** FAIL (1/10)
- **Cases:** 9/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dyn_ashr64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_dyn_ashr64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dyn_ashr64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dyn_ashr64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: byte0=1 xor byte1=0 |
| 3 | RCX=2 | 3 | 3 | 3 | yes | x=2 n=3 |
| 4 | RCX=7 | 5 | 5 | 5 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: byte0 of x |
| 6 | RCX=3405691582 | 141 | 141 | 141 | yes | 0xCAFEBABE: n=7 mixed shifts |
| 7 | RCX=3735928559 | 97 | 97 | 97 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 0 | 0 | _err: lli exited 1: C:\Users\Yusuf\Desktop\mergenrewrite\llvm18-install\bin\lli.exe: lli: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_dyn_ashr64_loop_eq.ll: error: Could not open input file_ | **no** | all 0xFF: ashr fills 1s; 8 xor of 0xFF cancel to 0 |
| 9 | RCX=9223372036854775808 | 0 | 0 | 0 | yes | x=2^63 n=1: byte0=0 single iter (high bit only) |
| 10 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | 0x12345...EF0: n=1 byte0=0xF0 |

## Failure detail

### case 8: all 0xFF: ashr fills 1s; 8 xor of 0xFF cancel to 0

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`
- lifted error: `lli exited 1: C:\Users\Yusuf\Desktop\mergenrewrite\llvm18-install\bin\lli.exe: lli: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_dyn_ashr64_loop_eq.ll: error: Could not open input file`

## Source

```c
/* PC-state VM running a dynamic-amount ASHR (signed shift right) and
 * XOR-fold of the low byte over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     int64_t sx = (int64_t)x >> i;       // dynamic ashr by i
 *     r = r ^ ((uint64_t)sx & 0xFF);
 *   }
 *   return r;
 *
 * Lift target: vm_dyn_ashr64_loop_target.
 *
 * Distinct from:
 *   - vm_bitfetch_window64_loop  (dynamic LSHR by counter)
 *   - vm_dynshl_pack64_loop      (dynamic SHL by counter)
 *   - vm_zigzag_step64_loop      (constant ashr-by-63)
 *
 * Completes the dynamic-shift trio (lshr / shl / ashr) for tests of
 * `ashr i64 x, %i` where %i is the loop-index phi.  Sign-extends the
 * input one position-shift further each iteration; the low byte
 * captures the moving signed window.  Negative inputs (high bit set)
 * fill with 1s, leading to different XOR patterns than unsigned shift.
 */
#include <stdio.h>
#include <stdint.h>

enum DaVmPc {
    DA_INIT_ALL = 0,
    DA_CHECK    = 1,
    DA_BODY     = 2,
    DA_INC      = 3,
    DA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dyn_ashr64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            int64_t sx = (int64_t)x >> (int)i;
            r = r ^ ((uint64_t)sx & 0xFFull);
            pc = DA_INC;
        } else if (pc == DA_INC) {
            i = i + 1ull;
            pc = DA_CHECK;
        } else if (pc == DA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dyn_ashr64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_dyn_ashr64_loop_target(0xDEADBEEFull));
    return 0;
}
```
