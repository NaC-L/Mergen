# vm_skiploop_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_skiploop_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_skiploop_loop.ll`
- **Symbol:** `vm_skiploop_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_skiploop_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_skiploop_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | limit=1: only i=0 (squares 0) |
| 3 | RCX=2 | 0 | 0 | 0 | yes | limit=2 |
| 4 | RCX=3 | 4 | 4 | 4 | yes | limit=3: 0+4 |
| 5 | RCX=5 | 20 | 20 | 20 | yes | limit=5: 0+4+16 |
| 6 | RCX=10 | 120 | 120 | 120 | yes | limit=10 |
| 7 | RCX=11 | 220 | 220 | 220 | yes | limit=11 |
| 8 | RCX=20 | 1140 | 1140 | 1140 | yes | limit=20 |
| 9 | RCX=50 | 19600 | 19600 | 19600 | yes | limit=50 |
| 10 | RCX=100 | 161700 | 161700 | 161700 | yes | limit=100 |
| 11 | RCX=255 | 2763520 | 2763520 | 2763520 | yes | limit=255 |

## Source

```c
/* PC-state VM running a counted loop where odd iterations are skipped
 * (continue-style flow control), accumulating squares of even indices.
 * Lift target: vm_skiploop_loop_target.
 * Goal: cover a dispatcher transition that returns directly to the loop
 * header CHECK from the body's parity test, skipping the accumulator
 * update entirely on odd iterations.  Distinct from vm_dual_counter_loop
 * (always-increment one of two counters) and vm_zigzag_loop (always-write
 * with sign flip) because here some iterations contribute nothing at all.
 */
#include <stdio.h>

enum SkVmPc {
    SK_LOAD       = 0,
    SK_INIT       = 1,
    SK_CHECK      = 2,
    SK_TEST_PAR   = 3,
    SK_BODY_SQ    = 4,
    SK_BODY_ADD   = 5,
    SK_BODY_INC   = 6,
    SK_HALT       = 7,
};

__declspec(noinline)
int vm_skiploop_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int sq    = 0;
    int pc    = SK_LOAD;

    while (1) {
        if (pc == SK_LOAD) {
            limit = x & 0xFF;
            idx = 0;
            sum = 0;
            pc = SK_INIT;
        } else if (pc == SK_INIT) {
            pc = SK_CHECK;
        } else if (pc == SK_CHECK) {
            pc = (idx < limit) ? SK_TEST_PAR : SK_HALT;
        } else if (pc == SK_TEST_PAR) {
            pc = ((idx & 1) != 0) ? SK_BODY_INC : SK_BODY_SQ;
        } else if (pc == SK_BODY_SQ) {
            sq = idx * idx;
            pc = SK_BODY_ADD;
        } else if (pc == SK_BODY_ADD) {
            sum = sum + sq;
            pc = SK_BODY_INC;
        } else if (pc == SK_BODY_INC) {
            idx = idx + 1;
            pc = SK_CHECK;
        } else if (pc == SK_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_skiploop_loop(11)=%d vm_skiploop_loop(50)=%d\n",
           vm_skiploop_loop_target(11), vm_skiploop_loop_target(50));
    return 0;
}
```
