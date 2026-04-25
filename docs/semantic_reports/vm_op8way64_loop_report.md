# vm_op8way64_loop - original vs lifted equivalence

- **Verdict:** FAIL (10/10)
- **Cases:** 0/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_op8way64_loop.c`
- **Lifted IR:** _(missing)_
- **Symbol:** `vm_op8way64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_op8way64_loop_eq.exe`

**Diagnostics:**
- lifted IR missing: C:\Users\Yusuf\Desktop\mergenrewrite\rewrite-regression-work\ir_outputs\vm_op8way64_loop.ll

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_op8way64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | — | **no** | x=0, n=1, op=0: s=0+1=1 |
| 2 | RCX=1 | 1 | 1 | — | **no** | x=1, n=2: op=1 then op=0 |
| 3 | RCX=7 | 7 | 7 | — | **no** | x=7, n=8 |
| 4 | RCX=15 | 14 | 14 | — | **no** | x=0xF, n=16 |
| 5 | RCX=51966 | 17870283321406128133 | 17870283321406128133 | — | **no** | x=0xCAFE, n=15 |
| 6 | RCX=3405691582 | 17328725466221477723 | 17328725466221477723 | — | **no** | x=0xCAFEBABE, n=15 |
| 7 | RCX=1311768467463790320 | 1 | 1 | — | **no** | 0x123...DEF0, n=1, op=0 |
| 8 | RCX=18446744073709551615 | 0 | 0 | — | **no** | max u64, n=16: every op=7 -> s ^= s>>5 |
| 9 | RCX=11400714819323198485 | 3558795033804543995 | 3558795033804543995 | — | **no** | K (golden), n=6 |
| 10 | RCX=6172840429334713770 | 32 | 32 | — | **no** | 0x55AA55AA55AA55AA, n=11 |

## Failure detail

### case 1: x=0, n=1, op=0: s=0+1=1

- inputs: `RCX=0`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 2: x=1, n=2: op=1 then op=0

- inputs: `RCX=1`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 3: x=7, n=8

- inputs: `RCX=7`
- manifest expected: `7`
- native: `7`
- lifted: `—`

### case 4: x=0xF, n=16

- inputs: `RCX=15`
- manifest expected: `14`
- native: `14`
- lifted: `—`

### case 5: x=0xCAFE, n=15

- inputs: `RCX=51966`
- manifest expected: `17870283321406128133`
- native: `17870283321406128133`
- lifted: `—`

### case 6: x=0xCAFEBABE, n=15

- inputs: `RCX=3405691582`
- manifest expected: `17328725466221477723`
- native: `17328725466221477723`
- lifted: `—`

### case 7: 0x123...DEF0, n=1, op=0

- inputs: `RCX=1311768467463790320`
- manifest expected: `1`
- native: `1`
- lifted: `—`

### case 8: max u64, n=16: every op=7 -> s ^= s>>5

- inputs: `RCX=18446744073709551615`
- manifest expected: `0`
- native: `0`
- lifted: `—`

### case 9: K (golden), n=6

- inputs: `RCX=11400714819323198485`
- manifest expected: `3558795033804543995`
- native: `3558795033804543995`
- lifted: `—`

### case 10: 0x55AA55AA55AA55AA, n=11

- inputs: `RCX=6172840429334713770`
- manifest expected: `32`
- native: `32`
- lifted: `—`

## Source

```c
/* PC-state VM with an 8-way value-driven switch dispatch in body
 * driven by 3-bit fields of x.  Eight distinct i64 update shapes
 * per opcode (add/mul/xor/sub/rotr/add-loop/not/xorshift).
 *   for i in 0..n:
 *     op = (x >> (i*3)) & 7
 *     switch (op) { 0:s+=1; 1:s*=2; 2:s^=x; 3:s-=7;
 *                   4:s=rotr1(s); 5:s+=i; 6:s=~s; 7:s^=s>>5; }
 * Variable trip n=(x&0xF)+1 (1..16).
 * Lift target: vm_op8way64_loop_target.
 *
 * Distinct from vm_opcode64_loop (4-way switch): denser switch with 8
 * branches and a wider variety of i64 op kinds (rotation, bitwise NOT,
 * mixed shift+xor) per opcode.
 */
#include <stdio.h>
#include <stdint.h>

enum O8VmPc {
    O8_LOAD       = 0,
    O8_INIT       = 1,
    O8_LOOP_CHECK = 2,
    O8_LOOP_BODY  = 3,
    O8_LOOP_INC   = 4,
    O8_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_op8way64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t s   = 0;
    int      pc  = O8_LOAD;

    while (1) {
        if (pc == O8_LOAD) {
            xx = x;
            n  = (int)(x & 0xFull) + 1;
            s  = 0ull;
            pc = O8_INIT;
        } else if (pc == O8_INIT) {
            idx = 0;
            pc = O8_LOOP_CHECK;
        } else if (pc == O8_LOOP_CHECK) {
            pc = (idx < n) ? O8_LOOP_BODY : O8_HALT;
        } else if (pc == O8_LOOP_BODY) {
            uint64_t op = (xx >> (idx * 3)) & 7ull;
            if      (op == 0ull) s = s + 1ull;
            else if (op == 1ull) s = s * 2ull;
            else if (op == 2ull) s = s ^ xx;
            else if (op == 3ull) s = s - 7ull;
            else if (op == 4ull) s = (s >> 1) | (s << 63);
            else if (op == 5ull) s = s + (uint64_t)idx;
            else if (op == 6ull) s = ~s;
            else                 s = s ^ (s >> 5);
            pc = O8_LOOP_INC;
        } else if (pc == O8_LOOP_INC) {
            idx = idx + 1;
            pc = O8_LOOP_CHECK;
        } else if (pc == O8_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_op8way64(0xCAFE)=%llu vm_op8way64(0x55AA55AA55AA55AA)=%llu\n",
           (unsigned long long)vm_op8way64_loop_target(0xCAFEull),
           (unsigned long long)vm_op8way64_loop_target(0x55AA55AA55AA55AAull));
    return 0;
}
```
