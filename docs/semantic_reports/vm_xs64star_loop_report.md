# vm_xs64star_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xs64star_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xs64star_loop.ll`
- **Symbol:** `vm_xs64star_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xs64star_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xs64star_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 5180492295206395165 | 5180492295206395165 | 5180492295206395165 | yes | x=0: state init=1, n=1 |
| 2 | RCX=1 | 12380297144915551517 | 12380297144915551517 | 12380297144915551517 | yes | x=1, n=2 |
| 3 | RCX=7 | 3148967184850244932 | 3148967184850244932 | 3148967184850244932 | yes | x=7, n=8 max |
| 4 | RCX=255 | 4236213719327884607 | 4236213719327884607 | 4236213719327884607 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 1645036189972921058 | 1645036189972921058 | 1645036189972921058 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 11951665673497468471 | 11951665673497468471 | 11951665673497468471 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 8076700419348325916 | 8076700419348325916 | 8076700419348325916 | yes | 0x123...DEF0, n=1 |
| 8 | RCX=18446744073709551615 | 9221922101790188898 | 9221922101790188898 | 9221922101790188898 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 11378009173764233326 | 11378009173764233326 | 11378009173764233326 | yes | K (golden), n=6 |
| 10 | RCX=3735928559 | 3885504143488397937 | 3885504143488397937 | 3885504143488397937 | yes | x=0xDEADBEEF, n=8 |

## Source

```c
/* PC-state VM running Marsaglia xorshift64* (xorshift body 12/25/27 +
 * final multiply by 0x2545F4914F6CDD1D).
 *   state = x | 1;
 *   for i in 0..n: { state ^= state >> 12; state ^= state << 25; state ^= state >> 27; }
 *   return state * 0x2545F4914F6CDD1D;
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_xs64star_loop_target.
 *
 * Distinct from vm_xorshift64_loop (13/7/17 shifts, no final mul) and
 * vm_pcg64_loop (mul-then-xor): different shift triple plus a final
 * post-loop multiplication by a 64-bit constant for output mixing.
 */
#include <stdio.h>
#include <stdint.h>

enum XsVmPc {
    XS_LOAD       = 0,
    XS_INIT       = 1,
    XS_LOOP_CHECK = 2,
    XS_LOOP_BODY  = 3,
    XS_LOOP_INC   = 4,
    XS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xs64star_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = XS_LOAD;

    while (1) {
        if (pc == XS_LOAD) {
            state = x | 1ull;
            n     = (int)(x & 7ull) + 1;
            pc = XS_INIT;
        } else if (pc == XS_INIT) {
            idx = 0;
            pc = XS_LOOP_CHECK;
        } else if (pc == XS_LOOP_CHECK) {
            pc = (idx < n) ? XS_LOOP_BODY : XS_HALT;
        } else if (pc == XS_LOOP_BODY) {
            state = state ^ (state >> 12);
            state = state ^ (state << 25);
            state = state ^ (state >> 27);
            pc = XS_LOOP_INC;
        } else if (pc == XS_LOOP_INC) {
            idx = idx + 1;
            pc = XS_LOOP_CHECK;
        } else if (pc == XS_HALT) {
            return state * 0x2545F4914F6CDD1Dull;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xs64star(0xCAFE)=%llu vm_xs64star(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_xs64star_loop_target(0xCAFEull),
           (unsigned long long)vm_xs64star_loop_target(0xDEADBEEFull));
    return 0;
}
```
