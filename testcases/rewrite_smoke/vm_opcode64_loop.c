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
