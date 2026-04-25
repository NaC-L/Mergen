# vm_threereg64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_threereg64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_threereg64_loop.ll`
- **Symbol:** `vm_threereg64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_threereg64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_threereg64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 3405691582 | 3405691582 | 3405691582 | yes | x=0, n=1, op=0: r0=0+~0=max; xor result = 0xCAFEBABE |
| 2 | RCX=1 | 3405691580 | 3405691580 | 3405691580 | yes | x=1, n=2 |
| 3 | RCX=7 | 20434149558 | 20434149558 | 20434149558 | yes | x=7, n=8 max |
| 4 | RCX=255 | 18446742981898582337 | 18446742981898582337 | 18446742981898582337 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 5809973315320979908 | 5809973315320979908 | 5809973315320979908 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 10576678296716486023 | 10576678296716486023 | 10576678296716486023 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 3405691582 | 3405691582 | 3405691582 | yes | 0x123...DEF0, n=1, op=0 |
| 8 | RCX=18446744073709551615 | 18446744070303860033 | 18446744070303860033 | 18446744070303860033 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 11697195004242549949 | 11697195004242549949 | 11697195004242549949 | yes | K (golden), n=6 |
| 10 | RCX=21930 | 18446744070303780845 | 18446744070303780845 | 18446744070303780845 | yes | x=0x55AA, n=3 |

## Source

```c
/* PC-state VM that simulates a tiny 3-register virtual machine.  The
 * outer dispatcher cycles on its own PC; inside the body, a 2-bit
 * opcode field of x selects one of four micro-ops, each updating a
 * single register (no mid-body compound cross-update).
 *   r0 = x;  r1 = ~x;  r2 = x ^ 0xCAFEBABE;
 *   for i in 0..n (n = (x & 7) + 1):
 *     op = (x >> (i*2)) & 3
 *     switch op:
 *       0: r0 = r0 + r1
 *       1: r1 = r1 ^ r2
 *       2: r2 = r2 + r0
 *       3: r0 = r0 * r1
 *   return r0 ^ r1 ^ r2;
 * Lift target: vm_threereg64_loop_target.
 *
 * Distinct from vm_op8way64_loop (single state, 8-way ops on one slot)
 * and vm_4state64_loop (single-direction phi shift): three independent
 * i64 registers updated by a per-iteration 4-way switch.  Each op
 * writes ONLY one slot to avoid the dual-i64 pseudo-stack failure.
 */
#include <stdio.h>
#include <stdint.h>

enum TrVmPc {
    TR_LOAD       = 0,
    TR_INIT       = 1,
    TR_LOOP_CHECK = 2,
    TR_LOOP_BODY  = 3,
    TR_LOOP_INC   = 4,
    TR_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_threereg64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t r0  = 0;
    uint64_t r1  = 0;
    uint64_t r2  = 0;
    int      pc  = TR_LOAD;

    while (1) {
        if (pc == TR_LOAD) {
            xx = x;
            r0 = x;
            r1 = ~x;
            r2 = x ^ 0xCAFEBABEull;
            n  = (int)(x & 7ull) + 1;
            pc = TR_INIT;
        } else if (pc == TR_INIT) {
            idx = 0;
            pc = TR_LOOP_CHECK;
        } else if (pc == TR_LOOP_CHECK) {
            pc = (idx < n) ? TR_LOOP_BODY : TR_HALT;
        } else if (pc == TR_LOOP_BODY) {
            uint64_t op = (xx >> (idx * 2)) & 3ull;
            if      (op == 0ull) r0 = r0 + r1;
            else if (op == 1ull) r1 = r1 ^ r2;
            else if (op == 2ull) r2 = r2 + r0;
            else                 r0 = r0 * r1;
            pc = TR_LOOP_INC;
        } else if (pc == TR_LOOP_INC) {
            idx = idx + 1;
            pc = TR_LOOP_CHECK;
        } else if (pc == TR_HALT) {
            return r0 ^ r1 ^ r2;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_threereg64(0xCAFE)=%llu vm_threereg64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_threereg64_loop_target(0xCAFEull),
           (unsigned long long)vm_threereg64_loop_target(0xCAFEBABEull));
    return 0;
}
```
