# vm_stride_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_stride_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_stride_loop.ll`
- **Symbol:** `vm_stride_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_stride_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_stride_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, data=[0] |
| 2 | RCX=1 | 1 | 1 | 1 | yes | limit=2: only data[0] |
| 3 | RCX=2 | 184 | 184 | 184 | yes | limit=3: data[0]+data[2] |
| 4 | RCX=7 | 324 | 324 | 324 | yes | limit=8: data[0,2,4,6] |
| 5 | RCX=170 | 200 | 200 | 200 | yes | 0xAA: limit=3 |
| 6 | RCX=85 | 371 | 371 | 371 | yes | 0x55: limit=6 |
| 7 | RCX=255 | 708 | 708 | 708 | yes | 0xFF: limit=8 |
| 8 | RCX=291 | 186 | 186 | 186 | yes | 0x123: limit=4 |
| 9 | RCX=74565 | 355 | 355 | 355 | yes | 0x12345: limit=6 |
| 10 | RCX=16777215 | 708 | 708 | 708 | yes | 0xFFFFFF: limit=8 |
| 11 | RCX=11259375 | 708 | 708 | 708 | yes | 0xABCDEF: limit=8 |
| 12 | RCX=192 | 192 | 192 | 192 | yes | 0xC0: limit=1 |

## Source

```c
/* PC-state VM that sums every other element of a symbolic-content stack
 * array (stride-2 induction).
 * Lift target: vm_stride_loop_target.
 * Goal: cover a counted loop where the induction variable increments by 2
 * per iteration (BODY_INC: idx += 2).  Distinct from vm_skiploop_loop
 * (which still increments by 1 and skips body via parity branch) because
 * here the induction step itself is 2.
 */
#include <stdio.h>

enum SdVmPc {
    SD_LOAD       = 0,
    SD_INIT_FILL  = 1,
    SD_FILL_CHECK = 2,
    SD_FILL_BODY  = 3,
    SD_FILL_INC   = 4,
    SD_INIT_SUM   = 5,
    SD_SUM_CHECK  = 6,
    SD_SUM_BODY   = 7,
    SD_SUM_INC    = 8,
    SD_HALT       = 9,
};

__declspec(noinline)
int vm_stride_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int pc    = SD_LOAD;

    while (1) {
        if (pc == SD_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = SD_INIT_FILL;
        } else if (pc == SD_INIT_FILL) {
            idx = 0;
            pc = SD_FILL_CHECK;
        } else if (pc == SD_FILL_CHECK) {
            pc = (idx < limit) ? SD_FILL_BODY : SD_INIT_SUM;
        } else if (pc == SD_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x5A)) & 0xFF;
            pc = SD_FILL_INC;
        } else if (pc == SD_FILL_INC) {
            idx = idx + 1;
            pc = SD_FILL_CHECK;
        } else if (pc == SD_INIT_SUM) {
            idx = 0;
            pc = SD_SUM_CHECK;
        } else if (pc == SD_SUM_CHECK) {
            pc = (idx < limit) ? SD_SUM_BODY : SD_HALT;
        } else if (pc == SD_SUM_BODY) {
            sum = sum + data[idx];
            pc = SD_SUM_INC;
        } else if (pc == SD_SUM_INC) {
            idx = idx + 2;
            pc = SD_SUM_CHECK;
        } else if (pc == SD_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_stride_loop(0xFF)=%d vm_stride_loop(0xABCDEF)=%d\n",
           vm_stride_loop_target(0xFF), vm_stride_loop_target(0xABCDEF));
    return 0;
}
```
