/* Minimal single-depth call/return VM with one-deep return PC slot.
 *   The dispatcher reads the next PC from a local variable `rpc` after
 *   a "call" opcode sets it. This is the simplest form of indirect
 *   dispatch through a stored PC — the pattern that previously crashed
 *   the lifter with an access violation.
 *
 * Trip count: n = (x & 0xF) + 1  (1..16).
 * Returns an accumulated hash value.
 * Lift target: vm_subroutine_loop_target.
 */
#include <stdio.h>
#include <stdint.h>

enum SubVmPc {
    SUB_LOAD       = 0,
    SUB_LOOP_CHECK = 1,
    SUB_CALL       = 2,
    SUB_BODY       = 3,
    SUB_RET        = 4,
    SUB_LOOP_INC   = 5,
    SUB_HALT       = 6,
};

__declspec(noinline)
uint64_t vm_subroutine_loop_target(uint64_t x) {
    int      pc   = SUB_LOAD;
    int      rpc  = 0;       /* one-deep return PC slot */
    int      idx  = 0;
    int      n    = 0;
    uint64_t acc  = 0;

    while (1) {
        if (pc == SUB_LOAD) {
            n   = (int)(x & 0xFull) + 1;
            acc = x;
            idx = 0;
            pc  = SUB_LOOP_CHECK;
        } else if (pc == SUB_LOOP_CHECK) {
            pc = (idx < n) ? SUB_CALL : SUB_HALT;
        } else if (pc == SUB_CALL) {
            /* "call" — save return PC and jump to subroutine */
            rpc = SUB_LOOP_INC;
            pc  = SUB_BODY;
        } else if (pc == SUB_BODY) {
            /* subroutine body: hash step */
            acc = acc ^ (acc << 13);
            acc = acc ^ (acc >> 7);
            acc = acc ^ (acc << 17);
            pc  = SUB_RET;
        } else if (pc == SUB_RET) {
            /* "ret" — indirect dispatch through rpc */
            pc = rpc;
        } else if (pc == SUB_LOOP_INC) {
            idx = idx + 1;
            pc  = SUB_LOOP_CHECK;
        } else if (pc == SUB_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("sub(1)=0x%llx sub(0xFF)=0x%llx\n",
           (unsigned long long)vm_subroutine_loop_target(1ull),
           (unsigned long long)vm_subroutine_loop_target(0xFFull));
    return 0;
}
