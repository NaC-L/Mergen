/* PC-state VM with explicit return-PC stack (call/ret via rstack[rsp]).
 *   The dispatcher reads the next PC from a stack array indexed by a
 *   VM stack pointer. Previously tripped BB budget exceeded (~4087 blocks)
 *   because indirect dispatch through a stack array was never generalized.
 *
 * Trip count: n = (x & 0xF) + 1  (1..16).
 * Returns accumulated xorshift hash.
 * Lift target: vm_callret_loop_target.
 */
#include <stdio.h>
#include <stdint.h>

enum CrVmPc {
    CR_LOAD       = 0,
    CR_LOOP_CHECK = 1,
    CR_PUSH_RET   = 2,
    CR_BODY       = 3,
    CR_POP_RET    = 4,
    CR_LOOP_INC   = 5,
    CR_HALT       = 6,
};

__declspec(noinline)
uint64_t vm_callret_loop_target(uint64_t x) {
    int      pc        = CR_LOAD;
    int      rstack[4] = {0, 0, 0, 0};
    int      rsp       = 0;
    int      idx       = 0;
    int      n         = 0;
    uint64_t acc       = 0;

    while (1) {
        if (pc == CR_LOAD) {
            n   = (int)(x & 0xFull) + 1;
            acc = x;
            idx = 0;
            rsp = 0;
            pc  = CR_LOOP_CHECK;
        } else if (pc == CR_LOOP_CHECK) {
            pc = (idx < n) ? CR_PUSH_RET : CR_HALT;
        } else if (pc == CR_PUSH_RET) {
            /* push return address onto VM stack */
            rstack[rsp] = CR_LOOP_INC;
            rsp = (rsp + 1) & 3;
            pc  = CR_BODY;
        } else if (pc == CR_BODY) {
            acc = acc ^ (acc << 13);
            acc = acc ^ (acc >> 7);
            acc = acc ^ (acc << 17);
            pc  = CR_POP_RET;
        } else if (pc == CR_POP_RET) {
            /* pop return address — indirect dispatch through stack */
            rsp = (rsp - 1) & 3;
            pc  = rstack[rsp];
        } else if (pc == CR_LOOP_INC) {
            idx = idx + 1;
            pc  = CR_LOOP_CHECK;
        } else if (pc == CR_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("cr(1)=0x%llx cr(0xFF)=0x%llx\n",
           (unsigned long long)vm_callret_loop_target(1ull),
           (unsigned long long)vm_callret_loop_target(0xFFull));
    return 0;
}
