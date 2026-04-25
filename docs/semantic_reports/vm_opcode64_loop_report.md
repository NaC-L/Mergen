# vm_opcode64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_opcode64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_opcode64_loop.ll`
- **Symbol:** `vm_opcode64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_opcode64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_opcode64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | x=0, n=1, op=0: s=0+1=1 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, n=2: op=1 then op=0 -> 0*2=0, +1=1 |
| 3 | RCX=2 | 4 | 4 | 4 | yes | x=2, n=3 |
| 4 | RCX=3 | 18446744073709551612 | 18446744073709551612 | 18446744073709551612 | yes | x=3, n=4: -7 underflow |
| 5 | RCX=15 | 8 | 8 | 8 | yes | x=0xF, n=16: 1 set nibble + zeros |
| 6 | RCX=51966 | 21 | 21 | 21 | yes | x=0xCAFE, n=15 |
| 7 | RCX=3405691582 | 19 | 19 | 19 | yes | x=0xCAFEBABE, n=15 |
| 8 | RCX=1311768467463790320 | 1 | 1 | 1 | yes | 0x123...DEF0, n=1, op=0: s=1 |
| 9 | RCX=18446744073709551615 | 18446744073709551504 | 18446744073709551504 | 18446744073709551504 | yes | max u64, n=16: every op=3 -> -7*16=-112 |
| 10 | RCX=11400714819323198485 | 7046029254386353136 | 7046029254386353136 | 7046029254386353136 | yes | K (golden), n=6 |

## Source

```c
/* PC-state VM that interprets 2-bit opcode fields of x as a 4-way
 * switch dispatch in the loop body.
 *   s = 0;  n = (x & 0xF) + 1;
 *   for i in 0..n:
 *     op = (x >> (i*4)) & 3
 *     switch (op) {
 *       case 0: s = s + 1;
 *       case 1: s = s * 2;
 *       case 2: s = s ^ x;
 *       case 3: s = s - 7;
 *     }
 *   return s;
 * Lift target: vm_opcode64_loop_target.
 *
 * Distinct from vm_treepath64_loop (binary branch on single bit) and
 * the failed vm_switch_dispatch_loop (VM-pc level switch).  Here the
 * switch is a per-iteration value-driven 4-way dispatch on extracted
 * opcode bits.  Body has 4 distinct i64 update shapes.
 */
#include <stdio.h>
#include <stdint.h>

enum OpVmPc {
    OP_LOAD       = 0,
    OP_INIT       = 1,
    OP_LOOP_CHECK = 2,
    OP_LOOP_BODY  = 3,
    OP_LOOP_INC   = 4,
    OP_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_opcode64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t s   = 0;
    int      pc  = OP_LOAD;

    while (1) {
        if (pc == OP_LOAD) {
            xx = x;
            n  = (int)(x & 0xFull) + 1;
            s  = 0ull;
            pc = OP_INIT;
        } else if (pc == OP_INIT) {
            idx = 0;
            pc = OP_LOOP_CHECK;
        } else if (pc == OP_LOOP_CHECK) {
            pc = (idx < n) ? OP_LOOP_BODY : OP_HALT;
        } else if (pc == OP_LOOP_BODY) {
            uint64_t op = (xx >> (idx * 4)) & 3ull;
            if (op == 0ull) {
                s = s + 1ull;
            } else if (op == 1ull) {
                s = s * 2ull;
            } else if (op == 2ull) {
                s = s ^ xx;
            } else {
                s = s - 7ull;
            }
            pc = OP_LOOP_INC;
        } else if (pc == OP_LOOP_INC) {
            idx = idx + 1;
            pc = OP_LOOP_CHECK;
        } else if (pc == OP_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_opcode64(0xCAFE)=%llu vm_opcode64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_opcode64_loop_target(0xCAFEull),
           (unsigned long long)vm_opcode64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
