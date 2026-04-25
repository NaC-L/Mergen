/* PC-state VM running an additive (Caesar-style) shift transform on a stack
 * buffer.
 * Lift target: vm_caesar_loop_target.
 * Goal: cover a two-phase VM (fill, transform-in-place, sum) where the
 * transformation is ADD+MASK rather than XOR.  Distinct from
 * vm_xordecrypt_loop (XOR+sum).
 */
#include <stdio.h>

enum CsVmPc {
    CS_LOAD       = 0,
    CS_INIT_FILL  = 1,
    CS_FILL_CHECK = 2,
    CS_FILL_BODY  = 3,
    CS_FILL_INC   = 4,
    CS_INIT_TX    = 5,
    CS_TX_CHECK   = 6,
    CS_TX_BODY    = 7,
    CS_TX_INC     = 8,
    CS_INIT_SUM   = 9,
    CS_SUM_CHECK  = 10,
    CS_SUM_BODY   = 11,
    CS_SUM_INC    = 12,
    CS_HALT       = 13,
};

__declspec(noinline)
int vm_caesar_loop_target(int x) {
    int buf[8];
    int idx     = 0;
    int shift   = 0;
    int byte    = 0;
    int sum     = 0;
    int pc      = CS_LOAD;

    while (1) {
        if (pc == CS_LOAD) {
            shift = (x >> 8) & 0x1F;
            sum = 0;
            pc = CS_INIT_FILL;
        } else if (pc == CS_INIT_FILL) {
            idx = 0;
            pc = CS_FILL_CHECK;
        } else if (pc == CS_FILL_CHECK) {
            pc = (idx < 8) ? CS_FILL_BODY : CS_INIT_TX;
        } else if (pc == CS_FILL_BODY) {
            buf[idx] = (x + idx * 0x11) & 0x1F;
            pc = CS_FILL_INC;
        } else if (pc == CS_FILL_INC) {
            idx = idx + 1;
            pc = CS_FILL_CHECK;
        } else if (pc == CS_INIT_TX) {
            idx = 0;
            pc = CS_TX_CHECK;
        } else if (pc == CS_TX_CHECK) {
            pc = (idx < 8) ? CS_TX_BODY : CS_INIT_SUM;
        } else if (pc == CS_TX_BODY) {
            byte = buf[idx];
            buf[idx] = (byte + shift) & 0x1F;
            pc = CS_TX_INC;
        } else if (pc == CS_TX_INC) {
            idx = idx + 1;
            pc = CS_TX_CHECK;
        } else if (pc == CS_INIT_SUM) {
            idx = 0;
            pc = CS_SUM_CHECK;
        } else if (pc == CS_SUM_CHECK) {
            pc = (idx < 8) ? CS_SUM_BODY : CS_HALT;
        } else if (pc == CS_SUM_BODY) {
            sum = sum + buf[idx];
            pc = CS_SUM_INC;
        } else if (pc == CS_SUM_INC) {
            idx = idx + 1;
            pc = CS_SUM_CHECK;
        } else if (pc == CS_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_caesar_loop(0x108)=%d vm_caesar_loop(0x1234)=%d\n",
           vm_caesar_loop_target(0x108), vm_caesar_loop_target(0x1234));
    return 0;
}
