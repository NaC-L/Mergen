# vm_shiftmul_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_shiftmul_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_shiftmul_loop.ll`
- **Symbol:** `vm_shiftmul_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_shiftmul_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_shiftmul_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | a=0,b=0 |
| 2 | RCX=258 | 2 | 2 | 2 | yes | a=2,b=1 |
| 3 | RCX=515 | 6 | 6 | 6 | yes | a=3,b=2 |
| 4 | RCX=3855 | 225 | 225 | 225 | yes | a=15,b=15 |
| 5 | RCX=65535 | 65025 | 65025 | 65025 | yes | a=255,b=255 |
| 6 | RCX=16386 | 128 | 128 | 128 | yes | a=2,b=64 |
| 7 | RCX=32769 | 128 | 128 | 128 | yes | a=1,b=128 |
| 8 | RCX=43605 | 14450 | 14450 | 14450 | yes | a=0x55,b=0xAA |
| 9 | RCX=21930 | 14450 | 14450 | 14450 | yes | a=0xAA,b=0x55 |
| 10 | RCX=49344 | 36864 | 36864 | 36864 | yes | a=0xC0,b=0xC0 |
| 11 | RCX=33023 | 32640 | 32640 | 32640 | yes | a=0xFF,b=0x80 |

## Source

```c
/* PC-state VM running schoolbook shift-and-add multiplication.
 * Lift target: vm_shiftmul_loop_target.
 * Goal: cover an 8-trip loop whose body conditionally adds a shifted
 * multiplicand based on the LSB of a shifted multiplier - distinct from
 * vm_xor_accumulator (XOR not add) and vm_carrychain (no conditional add).
 * Inputs a = x & 0xFF and b = (x >> 8) & 0xFF; result is (a*b) & 0xFFFF.
 */
#include <stdio.h>

enum SmVmPc {
    SM_LOAD       = 0,
    SM_INIT       = 1,
    SM_CHECK      = 2,
    SM_BODY_BIT   = 3,
    SM_BODY_TEST  = 4,
    SM_BODY_SHIFT = 5,
    SM_BODY_ADD   = 6,
    SM_BODY_INC   = 7,
    SM_HALT       = 8,
};

__declspec(noinline)
int vm_shiftmul_loop_target(int x) {
    int a      = 0;
    int b      = 0;
    int i      = 0;
    int result = 0;
    int bit    = 0;
    int term   = 0;
    int pc     = SM_LOAD;

    while (1) {
        if (pc == SM_LOAD) {
            a = x & 0xFF;
            b = (x >> 8) & 0xFF;
            i = 0;
            result = 0;
            pc = SM_INIT;
        } else if (pc == SM_INIT) {
            pc = SM_CHECK;
        } else if (pc == SM_CHECK) {
            pc = (i < 8) ? SM_BODY_BIT : SM_HALT;
        } else if (pc == SM_BODY_BIT) {
            bit = (b >> i) & 1;
            pc = SM_BODY_TEST;
        } else if (pc == SM_BODY_TEST) {
            pc = (bit != 0) ? SM_BODY_SHIFT : SM_BODY_INC;
        } else if (pc == SM_BODY_SHIFT) {
            term = a << i;
            pc = SM_BODY_ADD;
        } else if (pc == SM_BODY_ADD) {
            result = result + term;
            pc = SM_BODY_INC;
        } else if (pc == SM_BODY_INC) {
            i = i + 1;
            pc = SM_CHECK;
        } else if (pc == SM_HALT) {
            return result & 0xFFFF;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_shiftmul_loop(0xFFFF)=%d vm_shiftmul_loop(0xAA55)=%d\n",
           vm_shiftmul_loop_target(0xFFFF), vm_shiftmul_loop_target(0xAA55));
    return 0;
}
```
