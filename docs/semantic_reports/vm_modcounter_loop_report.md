# vm_modcounter_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_modcounter_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_modcounter_loop.ll`
- **Symbol:** `vm_modcounter_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_modcounter_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_modcounter_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | n=0 |
| 2 | RCX=4096 | 1 | 1 | 1 | yes | counter=0,step=1,n=1 |
| 3 | RCX=8192 | 2 | 2 | 2 | yes | n=2 |
| 4 | RCX=28672 | 0 | 0 | 0 | yes | n=7: wraps |
| 5 | RCX=61440 | 1 | 1 | 1 | yes | n=15: 15%7=1 |
| 6 | RCX=62208 | 3 | 3 | 3 | yes | step=3,n=15: 45%7=3 |
| 7 | RCX=61968 | 5 | 5 | 5 | yes | 0xF210: counter=16,step=3,n=15 |
| 8 | RCX=62805 | 6 | 6 | 6 | yes | 0xF555 |
| 9 | RCX=65535 | 4 | 4 | 4 | yes | 0xFFFF |
| 10 | RCX=33023 | 4 | 4 | 4 | yes | 0x80FF |
| 11 | RCX=4660 | 6 | 6 | 6 | yes | 0x1234 |

## Source

```c
/* PC-state VM with a counter that wraps modulo 7 every iteration.
 * Lift target: vm_modcounter_loop_target.
 * Goal: cover a single-state recurrence whose body is one mod operation
 * per step (counter = (counter + step) % 7).  Distinct from vm_lcg_loop
 * (mul+add+mask) and vm_powermod_loop (mul+conditional-mod): the constant
 * divisor is non-power-of-two and the recurrence has no multiplication.
 */
#include <stdio.h>

enum McVmPc {
    MC_LOAD       = 0,
    MC_INIT       = 1,
    MC_CHECK      = 2,
    MC_BODY_ADD   = 3,
    MC_BODY_MOD   = 4,
    MC_BODY_DEC   = 5,
    MC_HALT       = 6,
};

__declspec(noinline)
int vm_modcounter_loop_target(int x) {
    int counter = 0;
    int step    = 0;
    int n       = 0;
    int tmp     = 0;
    int pc      = MC_LOAD;

    while (1) {
        if (pc == MC_LOAD) {
            counter = x & 0xFF;
            step = ((x >> 8) & 0xF) | 1;
            n = (x >> 12) & 0xF;
            pc = MC_INIT;
        } else if (pc == MC_INIT) {
            pc = MC_CHECK;
        } else if (pc == MC_CHECK) {
            pc = (n > 0) ? MC_BODY_ADD : MC_HALT;
        } else if (pc == MC_BODY_ADD) {
            tmp = counter + step;
            pc = MC_BODY_MOD;
        } else if (pc == MC_BODY_MOD) {
            counter = tmp % 7;
            pc = MC_BODY_DEC;
        } else if (pc == MC_BODY_DEC) {
            n = n - 1;
            pc = MC_CHECK;
        } else if (pc == MC_HALT) {
            return counter;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_modcounter_loop(0xF300)=%d vm_modcounter_loop(0x1234)=%d\n",
           vm_modcounter_loop_target(0xF300), vm_modcounter_loop_target(0x1234));
    return 0;
}
```
