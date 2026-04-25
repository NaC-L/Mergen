# vm_nested64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_nested64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_nested64_loop.ll`
- **Symbol:** `vm_nested64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_nested64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_nested64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0, a=1,b=1,s=0 |
| 2 | RCX=1 | 962 | 962 | 962 | yes | x=1, a=2,b=1 |
| 3 | RCX=7 | 5971184918795 | 5971184918795 | 5971184918795 | yes | x=7, a=8,b=1 |
| 4 | RCX=255 | 10894761712370600223 | 10894761712370600223 | 10894761712370600223 | yes | x=0xFF, a=8,b=8 (max 64) |
| 5 | RCX=51966 | 10483213562186932506 | 10483213562186932506 | 10483213562186932506 | yes | x=0xCAFE, a=7,b=8 (56 iters) |
| 6 | RCX=3405691582 | 17568069125822042330 | 17568069125822042330 | 17568069125822042330 | yes | 0xCAFEBABE, a=7,b=8 |
| 7 | RCX=1311768467463790320 | 81985057741989747 | 81985057741989747 | 81985057741989747 | yes | 0x123...DEF0, a=1,b=7 |
| 8 | RCX=18446744073709551615 | 5597661801495414815 | 5597661801495414815 | 5597661801495414815 | yes | max u64, a=8,b=8 |
| 9 | RCX=11400714819323198485 | 12085406143598956766 | 12085406143598956766 | 12085406143598956766 | yes | K (golden), a=6,b=3 (18 iters) |
| 10 | RCX=127 | 17469583793787783327 | 17469583793787783327 | 17469583793787783327 | yes | x=0x7F, a=8,b=8 |

## Source

```c
/* PC-state VM with a doubly-nested loop on full uint64_t state.  Both
 * outer and inner bounds derive from the input.
 *   a = (x & 7) + 1;            // outer trip 1..8
 *   b = ((x >> 3) & 7) + 1;     // inner trip 1..8
 *   s = x;
 *   for i in 0..a:
 *     for j in 0..b:
 *       s = s * 31 + (i*b + j);
 *   return s;
 * Total inner iterations 1..64.  Lift target: vm_nested64_loop_target.
 *
 * Distinct from vm_nested_loop (i32 state, simpler body): exercises a
 * full i64 mul-add recurrence inside doubly-nested PC-state loops with
 * both bounds symbolic.
 */
#include <stdio.h>
#include <stdint.h>

enum NsVmPc {
    NS_LOAD       = 0,
    NS_INIT_OUTER = 1,
    NS_OUTER_CHK  = 2,
    NS_INIT_INNER = 3,
    NS_INNER_CHK  = 4,
    NS_BODY       = 5,
    NS_INNER_INC  = 6,
    NS_OUTER_INC  = 7,
    NS_HALT       = 8,
};

__declspec(noinline)
uint64_t vm_nested64_loop_target(uint64_t x) {
    int      a = 0;
    int      b = 0;
    int      i = 0;
    int      j = 0;
    uint64_t s = 0;
    int      pc = NS_LOAD;

    while (1) {
        if (pc == NS_LOAD) {
            a = (int)(x & 7ull) + 1;
            b = (int)((x >> 3) & 7ull) + 1;
            s = x;
            pc = NS_INIT_OUTER;
        } else if (pc == NS_INIT_OUTER) {
            i = 0;
            pc = NS_OUTER_CHK;
        } else if (pc == NS_OUTER_CHK) {
            pc = (i < a) ? NS_INIT_INNER : NS_HALT;
        } else if (pc == NS_INIT_INNER) {
            j = 0;
            pc = NS_INNER_CHK;
        } else if (pc == NS_INNER_CHK) {
            pc = (j < b) ? NS_BODY : NS_OUTER_INC;
        } else if (pc == NS_BODY) {
            s = s * 31ull + (uint64_t)(i * b + j);
            pc = NS_INNER_INC;
        } else if (pc == NS_INNER_INC) {
            j = j + 1;
            pc = NS_INNER_CHK;
        } else if (pc == NS_OUTER_INC) {
            i = i + 1;
            pc = NS_OUTER_CHK;
        } else if (pc == NS_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_nested64(0xFF)=%llu vm_nested64(0xCAFE)=%llu\n",
           (unsigned long long)vm_nested64_loop_target(0xFFull),
           (unsigned long long)vm_nested64_loop_target(0xCAFEull));
    return 0;
}
```
