# vm_factorial64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_factorial64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_factorial64_loop.ll`
- **Symbol:** `vm_factorial64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_factorial64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_factorial64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | x=0, n=1: 1!=1 |
| 2 | RCX=1 | 2 | 2 | 2 | yes | x=1, n=2: 2!=2 |
| 3 | RCX=4 | 120 | 120 | 120 | yes | x=4, n=5: 5!=120 |
| 4 | RCX=9 | 3628800 | 3628800 | 3628800 | yes | x=9, n=10: 10! |
| 5 | RCX=11 | 479001600 | 479001600 | 479001600 | yes | x=11, n=12: 12! |
| 6 | RCX=19 | 2432902008176640000 | 2432902008176640000 | 2432902008176640000 | yes | x=19, n=20: 20! (last that fits u64) |
| 7 | RCX=20 | 14197454024290336768 | 14197454024290336768 | 14197454024290336768 | yes | x=20, n=21: 21! wraps mod 2^64 |
| 8 | RCX=25 | 16877220553537093632 | 16877220553537093632 | 16877220553537093632 | yes | x=25, n=26: 26! wraps |
| 9 | RCX=31 | 12400865694432886784 | 12400865694432886784 | 12400865694432886784 | yes | x=0x1F, n=32 max: 32! wraps |
| 10 | RCX=51966 | 4999213071378415616 | 4999213071378415616 | 4999213071378415616 | yes | x=0xCAFE, n=31 |

## Source

```c
/* PC-state VM running an i64 factorial.
 *   n = (x & 0x1F) + 1;     // 1..32
 *   r = 1;
 *   for i in 1..n+1: r = r * i;
 *   return r;     // wraps mod 2^64 for n >= 21
 * Lift target: vm_factorial64_loop_target.
 *
 * Distinct from vm_factorial_loop (i32 factorial): exercises i64 mul
 * inside a variable-trip loop with deliberate wrap (21! through 32!
 * exceed u64 range and wrap mod 2^64).
 */
#include <stdio.h>
#include <stdint.h>

enum FaVmPc {
    FA_LOAD       = 0,
    FA_INIT       = 1,
    FA_LOOP_CHECK = 2,
    FA_LOOP_BODY  = 3,
    FA_LOOP_INC   = 4,
    FA_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_factorial64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t r   = 0;
    int      pc  = FA_LOAD;

    while (1) {
        if (pc == FA_LOAD) {
            n = (int)(x & 0x1Full) + 1;
            r = 1ull;
            pc = FA_INIT;
        } else if (pc == FA_INIT) {
            idx = 1;
            pc = FA_LOOP_CHECK;
        } else if (pc == FA_LOOP_CHECK) {
            pc = (idx <= n) ? FA_LOOP_BODY : FA_HALT;
        } else if (pc == FA_LOOP_BODY) {
            r = r * (uint64_t)idx;
            pc = FA_LOOP_INC;
        } else if (pc == FA_LOOP_INC) {
            idx = idx + 1;
            pc = FA_LOOP_CHECK;
        } else if (pc == FA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_factorial64(20)=%llu vm_factorial64(21)=%llu\n",
           (unsigned long long)vm_factorial64_loop_target(19ull),  /* n=20 */
           (unsigned long long)vm_factorial64_loop_target(20ull)); /* n=21 wraps */
    return 0;
}
```
