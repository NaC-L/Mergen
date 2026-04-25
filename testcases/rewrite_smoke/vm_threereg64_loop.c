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
