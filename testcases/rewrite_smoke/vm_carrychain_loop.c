/* PC-state VM running an 8-bit ripple-carry adder bit-by-bit.
 * Lift target: vm_carrychain_loop_target.
 * Goal: cover a fixed-trip-count loop where each iteration depends on the
 * carry produced in the previous iteration (sequential dependency that
 * cannot be parallelised by the optimizer).  Inputs a = x & 0xFF and
 * b = (x >> 8) & 0xFF, output is (a+b) packed as low byte | (carry<<8).
 */
#include <stdio.h>

enum CcVmPc {
    CC_LOAD     = 0,
    CC_INIT     = 1,
    CC_CHECK    = 2,
    CC_BODY_BA  = 3,
    CC_BODY_BB  = 4,
    CC_BODY_SUM = 5,
    CC_BODY_NC  = 6,
    CC_BODY_OR  = 7,
    CC_BODY_INC = 8,
    CC_PACK     = 9,
    CC_HALT     = 10,
};

__declspec(noinline)
int vm_carrychain_loop_target(int x) {
    int a       = 0;
    int b       = 0;
    int i       = 0;
    int carry   = 0;
    int result  = 0;
    int ba      = 0;
    int bb      = 0;
    int bs      = 0;
    int nc      = 0;
    int xor_ab  = 0;
    int pc      = CC_LOAD;

    while (1) {
        if (pc == CC_LOAD) {
            a = x & 0xFF;
            b = (x >> 8) & 0xFF;
            i = 0;
            carry = 0;
            result = 0;
            pc = CC_INIT;
        } else if (pc == CC_INIT) {
            pc = CC_CHECK;
        } else if (pc == CC_CHECK) {
            pc = (i < 8) ? CC_BODY_BA : CC_PACK;
        } else if (pc == CC_BODY_BA) {
            ba = (a >> i) & 1;
            pc = CC_BODY_BB;
        } else if (pc == CC_BODY_BB) {
            bb = (b >> i) & 1;
            pc = CC_BODY_SUM;
        } else if (pc == CC_BODY_SUM) {
            xor_ab = ba ^ bb;
            bs = xor_ab ^ carry;
            pc = CC_BODY_NC;
        } else if (pc == CC_BODY_NC) {
            nc = (ba & bb) | (carry & xor_ab);
            pc = CC_BODY_OR;
        } else if (pc == CC_BODY_OR) {
            result = result | (bs << i);
            carry = nc;
            pc = CC_BODY_INC;
        } else if (pc == CC_BODY_INC) {
            i = i + 1;
            pc = CC_CHECK;
        } else if (pc == CC_PACK) {
            result = result | (carry << 8);
            pc = CC_HALT;
        } else if (pc == CC_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_carrychain_loop(0xFFFF)=%d vm_carrychain_loop(0xAA55)=%d\n",
           vm_carrychain_loop_target(0xFFFF), vm_carrychain_loop_target(0xAA55));
    return 0;
}
