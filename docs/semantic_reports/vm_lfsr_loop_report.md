# vm_lfsr_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_lfsr_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_lfsr_loop.ll`
- **Symbol:** `vm_lfsr_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_lfsr_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_lfsr_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | n=0: state=seed=1 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | n=0, seed forced to 1 |
| 3 | RCX=256 | 184 | 184 | 184 | yes | n=1, seed=1: 1 -> 0xB8 |
| 4 | RCX=257 | 184 | 184 | 184 | yes | n=1, seed=1 again |
| 5 | RCX=128 | 129 | 129 | 129 | yes | n=0, seed=0x81 |
| 6 | RCX=129 | 129 | 129 | 129 | yes | n=0, seed=0x81 (lsb forced) |
| 7 | RCX=512 | 92 | 92 | 92 | yes | n=2, seed=1: 1 -> 0xB8 -> 0x5C |
| 8 | RCX=1280 | 179 | 179 | 179 | yes | n=5, seed=1 |
| 9 | RCX=4095 | 117 | 117 | 117 | yes | n=15, seed=0xFF |
| 10 | RCX=4660 | 81 | 81 | 81 | yes | n=2, seed=0x35 |

## Source

```c
/* PC-state VM running an 8-bit Galois LFSR (PRNG-style bitwise recurrence).
 * Lift target: vm_lfsr_loop_target.
 * Goal: cover a loop whose body conditionally XORs a tap polynomial after a
 * shift, distinct from popcount (no XOR with constant) and bitreverse (no
 * conditional). Both seed and trip count are symbolic:
 *   seed = (x & 0xFF) | 1   (avoid zero state)
 *   n    = (x >> 8) & 0xF
 * Init dispatcher state pre-writes the loop variables (dual_counter pattern).
 */
#include <stdio.h>

enum LfsrVmPc {
    LF_INIT       = 0,
    LF_LOAD       = 1,
    LF_CHECK      = 2,
    LF_TEST_LSB   = 3,
    LF_BODY_XOR   = 4,
    LF_BODY_SHIFT = 5,
    LF_BODY_DEC   = 6,
    LF_HALT       = 7,
};

__declspec(noinline)
int vm_lfsr_loop_target(int x) {
    int state = 0;
    int n     = 0;
    int lsb   = 0;
    int pc    = LF_LOAD;

    while (1) {
        if (pc == LF_LOAD) {
            state = (x & 0xFF) | 1;
            n = (x >> 8) & 0xF;
            pc = LF_CHECK;
        } else if (pc == LF_CHECK) {
            pc = (n > 0) ? LF_TEST_LSB : LF_HALT;
        } else if (pc == LF_TEST_LSB) {
            lsb = state & 1;
            pc = (lsb != 0) ? LF_BODY_XOR : LF_BODY_SHIFT;
        } else if (pc == LF_BODY_XOR) {
            state = (int)((unsigned)state >> 1);
            state = (state ^ 0xB8) & 0xFF;
            pc = LF_BODY_DEC;
        } else if (pc == LF_BODY_SHIFT) {
            state = (int)((unsigned)state >> 1) & 0xFF;
            pc = LF_BODY_DEC;
        } else if (pc == LF_BODY_DEC) {
            n = n - 1;
            pc = LF_CHECK;
        } else if (pc == LF_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_lfsr_loop(0x500)=%d vm_lfsr_loop(0xFFF)=%d\n",
           vm_lfsr_loop_target(0x500), vm_lfsr_loop_target(0xFFF));
    return 0;
}
```
