# vm_xordecrypt_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xordecrypt_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xordecrypt_loop.ll`
- **Symbol:** `vm_xordecrypt_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xordecrypt_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xordecrypt_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1112 | 1112 | 1112 | yes | key=0: sum of (buf[i] ^ i) |
| 2 | RCX=1 | 1096 | 1096 | 1096 | yes | key=1 |
| 3 | RCX=51 | 1064 | 1064 | 1064 | yes | key=0x33 |
| 4 | RCX=85 | 936 | 936 | 936 | yes | key=0x55 |
| 5 | RCX=119 | 920 | 920 | 920 | yes | key=0x77 |
| 6 | RCX=127 | 856 | 856 | 856 | yes | key=0x7F |
| 7 | RCX=170 | 1112 | 1112 | 1112 | yes | key=0xAA |
| 8 | RCX=192 | 984 | 984 | 984 | yes | key=0xC0 |
| 9 | RCX=255 | 1112 | 1112 | 1112 | yes | key=0xFF |
| 10 | RCX=256 | 1112 | 1112 | 1112 | yes | key=0 again (mask drops bit 8) |

## Source

```c
/* PC-state VM that XOR-decrypts a stack buffer with a per-index varying key
 * and returns the sum.
 * Lift target: vm_xordecrypt_loop_target.
 * Goal: cover a two-phase VM: (1) initialize an 8-byte stack buffer with
 * fixed contents, (2) walk it XOR-ing each byte with (key + i) where the
 * key is symbolic, then sum.  Real obfuscation VMs use exactly this shape
 * to decrypt opcode tables before dispatch.
 */
#include <stdio.h>

enum XdVmPc {
    XD_LOAD       = 0,
    XD_INIT_FILL  = 1,
    XD_FILL_CHECK = 2,
    XD_FILL_BODY  = 3,
    XD_FILL_INC   = 4,
    XD_INIT_DEC   = 5,
    XD_DEC_CHECK  = 6,
    XD_DEC_LOAD   = 7,
    XD_DEC_KEY    = 8,
    XD_DEC_STORE  = 9,
    XD_DEC_INC    = 10,
    XD_INIT_SUM   = 11,
    XD_SUM_CHECK  = 12,
    XD_SUM_BODY   = 13,
    XD_SUM_INC    = 14,
    XD_HALT       = 15,
};

__declspec(noinline)
int vm_xordecrypt_loop_target(int x) {
    int buf[8];
    int idx     = 0;
    int key     = 0;
    int byte    = 0;
    int subkey  = 0;
    int sum     = 0;
    int pc      = XD_LOAD;

    while (1) {
        if (pc == XD_LOAD) {
            key = x & 0xFF;
            sum = 0;
            pc = XD_INIT_FILL;
        } else if (pc == XD_INIT_FILL) {
            idx = 0;
            pc = XD_FILL_CHECK;
        } else if (pc == XD_FILL_CHECK) {
            pc = (idx < 8) ? XD_FILL_BODY : XD_INIT_DEC;
        } else if (pc == XD_FILL_BODY) {
            buf[idx] = (idx * 0x33 + 0x77) & 0xFF;
            pc = XD_FILL_INC;
        } else if (pc == XD_FILL_INC) {
            idx = idx + 1;
            pc = XD_FILL_CHECK;
        } else if (pc == XD_INIT_DEC) {
            idx = 0;
            pc = XD_DEC_CHECK;
        } else if (pc == XD_DEC_CHECK) {
            pc = (idx < 8) ? XD_DEC_LOAD : XD_INIT_SUM;
        } else if (pc == XD_DEC_LOAD) {
            byte = buf[idx];
            pc = XD_DEC_KEY;
        } else if (pc == XD_DEC_KEY) {
            subkey = (key + idx) & 0xFF;
            pc = XD_DEC_STORE;
        } else if (pc == XD_DEC_STORE) {
            buf[idx] = byte ^ subkey;
            pc = XD_DEC_INC;
        } else if (pc == XD_DEC_INC) {
            idx = idx + 1;
            pc = XD_DEC_CHECK;
        } else if (pc == XD_INIT_SUM) {
            idx = 0;
            pc = XD_SUM_CHECK;
        } else if (pc == XD_SUM_CHECK) {
            pc = (idx < 8) ? XD_SUM_BODY : XD_HALT;
        } else if (pc == XD_SUM_BODY) {
            sum = sum + buf[idx];
            pc = XD_SUM_INC;
        } else if (pc == XD_SUM_INC) {
            idx = idx + 1;
            pc = XD_SUM_CHECK;
        } else if (pc == XD_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_xordecrypt_loop(0x55)=%d vm_xordecrypt_loop(0x7F)=%d\n",
           vm_xordecrypt_loop_target(0x55), vm_xordecrypt_loop_target(0x7F));
    return 0;
}
```
