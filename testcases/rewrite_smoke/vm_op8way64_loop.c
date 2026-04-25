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
