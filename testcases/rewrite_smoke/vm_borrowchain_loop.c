/* PC-state VM running an 8-bit ripple-borrow subtractor bit-by-bit.
 * Lift target: vm_borrowchain_loop_target.
 * Goal: complete the carrychain pair with a sequential subtractor where
 * each iteration's borrow depends on the previous bit's borrow.  Inputs
 * a = x & 0xFF and b = (x >> 8) & 0xFF, output is (a-b) mod 2^8 packed
 * as low byte | (final_borrow << 8).  Distinct from vm_carrychain_loop
 * (which adds): the borrow propagation chain has the opposite signal
 * pattern.
 *
 *   bs        = ba XOR bb XOR borrow            // sum bit of full subtractor
 *   new_borrow = (NOT ba AND bb) OR (borrow AND NOT(ba XOR bb))
 */
#include <stdio.h>

enum BcVmPc {
    BC2_LOAD     = 0,
    BC2_INIT     = 1,
    BC2_CHECK    = 2,
    BC2_BODY_BA  = 3,
    BC2_BODY_BB  = 4,
    BC2_BODY_SUM = 5,
    BC2_BODY_NB  = 6,
    BC2_BODY_OR  = 7,
    BC2_BODY_INC = 8,
    BC2_PACK     = 9,
    BC2_HALT     = 10,
};

__declspec(noinline)
int vm_borrowchain_loop_target(int x) {
    int a       = 0;
    int b       = 0;
    int i       = 0;
    int borrow  = 0;
    int result  = 0;
    int ba      = 0;
    int bb      = 0;
    int bs      = 0;
    int nb      = 0;
    int xor_ab  = 0;
    int pc      = BC2_LOAD;

    while (1) {
        if (pc == BC2_LOAD) {
            a = x & 0xFF;
            b = (x >> 8) & 0xFF;
            i = 0;
            borrow = 0;
            result = 0;
            pc = BC2_INIT;
        } else if (pc == BC2_INIT) {
            pc = BC2_CHECK;
        } else if (pc == BC2_CHECK) {
            pc = (i < 8) ? BC2_BODY_BA : BC2_PACK;
        } else if (pc == BC2_BODY_BA) {
            ba = (a >> i) & 1;
            pc = BC2_BODY_BB;
        } else if (pc == BC2_BODY_BB) {
            bb = (b >> i) & 1;
            pc = BC2_BODY_SUM;
        } else if (pc == BC2_BODY_SUM) {
            xor_ab = ba ^ bb;
            bs = xor_ab ^ borrow;
            pc = BC2_BODY_NB;
        } else if (pc == BC2_BODY_NB) {
            nb = ((~ba) & bb & 1) | (borrow & ((~xor_ab) & 1));
            pc = BC2_BODY_OR;
        } else if (pc == BC2_BODY_OR) {
            result = result | (bs << i);
            borrow = nb;
            pc = BC2_BODY_INC;
        } else if (pc == BC2_BODY_INC) {
            i = i + 1;
            pc = BC2_CHECK;
        } else if (pc == BC2_PACK) {
            result = result | (borrow << 8);
            pc = BC2_HALT;
        } else if (pc == BC2_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_borrowchain_loop(0x0001)=%d vm_borrowchain_loop(0xAA55)=%d\n",
           vm_borrowchain_loop_target(0x0001), vm_borrowchain_loop_target(0xAA55));
    return 0;
}
