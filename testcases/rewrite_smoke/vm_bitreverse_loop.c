/* PC-state VM that reverses the low 8 bits of x via shift+OR accumulation.
 * Lift target: vm_bitreverse_loop_target.
 * Goal: cover a fixed-trip-count loop whose body uses both shifts and a
 * bitwise OR to accumulate a result, exercising loop body shapes the
 * additive/multiplicative samples don't reach.
 */
#include <stdio.h>

enum BrVmPc {
    BRV_INIT       = 0,
    BRV_LOAD_VAL   = 1,
    BRV_INIT_RES   = 2,
    BRV_INIT_IDX   = 3,
    BRV_CHECK      = 4,
    BRV_BODY_SHL   = 5,
    BRV_BODY_BIT   = 6,
    BRV_BODY_OR    = 7,
    BRV_BODY_SHR   = 8,
    BRV_BODY_INC   = 9,
    BRV_HALT       = 10,
};

__declspec(noinline)
int vm_bitreverse_loop_target(int x) {
    int v   = 0;
    int res = 0;
    int idx = 0;
    int bit = 0;
    int pc  = BRV_INIT;

    while (1) {
        if (pc == BRV_INIT) {
            pc = BRV_LOAD_VAL;
        } else if (pc == BRV_LOAD_VAL) {
            v = x & 0xFF;
            pc = BRV_INIT_RES;
        } else if (pc == BRV_INIT_RES) {
            res = 0;
            pc = BRV_INIT_IDX;
        } else if (pc == BRV_INIT_IDX) {
            idx = 0;
            pc = BRV_CHECK;
        } else if (pc == BRV_CHECK) {
            pc = (idx < 8) ? BRV_BODY_SHL : BRV_HALT;
        } else if (pc == BRV_BODY_SHL) {
            res = res << 1;
            pc = BRV_BODY_BIT;
        } else if (pc == BRV_BODY_BIT) {
            bit = v & 1;
            pc = BRV_BODY_OR;
        } else if (pc == BRV_BODY_OR) {
            res = res | bit;
            pc = BRV_BODY_SHR;
        } else if (pc == BRV_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = BRV_BODY_INC;
        } else if (pc == BRV_BODY_INC) {
            idx = idx + 1;
            pc = BRV_CHECK;
        } else if (pc == BRV_HALT) {
            return res;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_bitreverse_loop(0xAA)=%d vm_bitreverse_loop(0x12)=%d\n",
           vm_bitreverse_loop_target(0xAA), vm_bitreverse_loop_target(0x12));
    return 0;
}
