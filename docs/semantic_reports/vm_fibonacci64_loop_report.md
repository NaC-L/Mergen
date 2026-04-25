# vm_fibonacci64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_fibonacci64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_fibonacci64_loop.ll`
- **Symbol:** `vm_fibonacci64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_fibonacci64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_fibonacci64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 14627333968688430831 | 14627333968688430831 | 14627333968688430831 | yes | x=0, trip=1: a=0, b=K_INIT |
| 2 | RCX=1 | 10807923863667310045 | 10807923863667310045 | 10807923863667310045 | yes | x=1, trip=2 |
| 3 | RCX=5 | 5687900855854084618 | 5687900855854084618 | 5687900855854084618 | yes | x=5, trip=6 |
| 4 | RCX=10 | 3407267088245154890 | 3407267088245154890 | 3407267088245154890 | yes | x=10, trip=11 |
| 5 | RCX=15 | 6274350679131682101 | 6274350679131682101 | 6274350679131682101 | yes | x=15, trip=16 |
| 6 | RCX=31 | 16253303666571051899 | 16253303666571051899 | 16253303666571051899 | yes | x=31, trip=32 |
| 7 | RCX=63 | 2638045729306583957 | 2638045729306583957 | 2638045729306583957 | yes | x=63, trip=64 max |
| 8 | RCX=51966 | 5669525655922824359 | 5669525655922824359 | 5669525655922824359 | yes | x=0xCAFE, trip=63 |
| 9 | RCX=3405691582 | 4673146425386425063 | 4673146425386425063 | 4673146425386425063 | yes | x=0xCAFEBABE, trip=63 |
| 10 | RCX=18446744073709551615 | 15808806811648464405 | 15808806811648464405 | 15808806811648464405 | yes | max u64, trip=64 |

## Source

```c
/* PC-state VM running a Fibonacci-shape recurrence on full uint64_t.
 *   a = x;  b = x ^ K_INIT;
 *   for i in 0..n: t = a + b; a = b; b = t;
 * Where n = (x & 0x3F) + 1 and K_INIT = 0xCAFEBABEDEADBEEF.
 * Returns final b as full uint64_t.
 * Lift target: vm_fibonacci64_loop_target.
 *
 * Distinct from vm_fibonacci_loop (i32 fib).  Both initial values and the
 * trip count derive from the full input; the recurrence wraps mod 2^64.
 */
#include <stdio.h>
#include <stdint.h>

enum F64VmPc {
    F64_LOAD       = 0,
    F64_INIT       = 1,
    F64_LOOP_CHECK = 2,
    F64_LOOP_BODY  = 3,
    F64_LOOP_INC   = 4,
    F64_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_fibonacci64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t a   = 0;
    uint64_t b   = 0;
    uint64_t t   = 0;
    int      pc  = F64_LOAD;

    while (1) {
        if (pc == F64_LOAD) {
            n = (int)(x & 0x3Full) + 1;
            a = x;
            b = x ^ 0xCAFEBABEDEADBEEFull;
            pc = F64_INIT;
        } else if (pc == F64_INIT) {
            idx = 0;
            pc = F64_LOOP_CHECK;
        } else if (pc == F64_LOOP_CHECK) {
            pc = (idx < n) ? F64_LOOP_BODY : F64_HALT;
        } else if (pc == F64_LOOP_BODY) {
            t = a + b;
            a = b;
            b = t;
            pc = F64_LOOP_INC;
        } else if (pc == F64_LOOP_INC) {
            idx = idx + 1;
            pc = F64_LOOP_CHECK;
        } else if (pc == F64_HALT) {
            return b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fib64(0xCAFE)=0x%llx vm_fib64(0xFF)=0x%llx\n",
           (unsigned long long)vm_fibonacci64_loop_target(0xCAFEull),
           (unsigned long long)vm_fibonacci64_loop_target(0xFFull));
    return 0;
}
```
