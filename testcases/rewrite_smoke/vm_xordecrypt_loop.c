/* PC-state VM that XOR-decrypts a stack buffer with a per-index varying key
 * and returns the sum.
 * Lift target: vm_xordecrypt_loop_target.
 * Goal: cover a two-phase VM: (1) initialize an 8-byte stack buffer with
 * fixed contents, (2) walk it XOR-ing each byte with (key + i) where the
 * key is symbolic, then sum.  Real obfuscation VMs use exactly this shape
 * to decrypt opcode tables before dispatch.
 */
#include <stdio.h>

enum XdVmPc {
    XD_LOAD       = 0,
    XD_INIT_FILL  = 1,
    XD_FILL_CHECK = 2,
    XD_FILL_BODY  = 3,
    XD_FILL_INC   = 4,
    XD_INIT_DEC   = 5,
    XD_DEC_CHECK  = 6,
    XD_DEC_LOAD   = 7,
    XD_DEC_KEY    = 8,
    XD_DEC_STORE  = 9,
    XD_DEC_INC    = 10,
    XD_INIT_SUM   = 11,
    XD_SUM_CHECK  = 12,
    XD_SUM_BODY   = 13,
    XD_SUM_INC    = 14,
    XD_HALT       = 15,
};

__declspec(noinline)
int vm_xordecrypt_loop_target(int x) {
    int buf[8];
    int idx     = 0;
    int key     = 0;
    int byte    = 0;
    int subkey  = 0;
    int sum     = 0;
    int pc      = XD_LOAD;

    while (1) {
        if (pc == XD_LOAD) {
            key = x & 0xFF;
            sum = 0;
            pc = XD_INIT_FILL;
        } else if (pc == XD_INIT_FILL) {
            idx = 0;
            pc = XD_FILL_CHECK;
        } else if (pc == XD_FILL_CHECK) {
            pc = (idx < 8) ? XD_FILL_BODY : XD_INIT_DEC;
        } else if (pc == XD_FILL_BODY) {
            buf[idx] = (idx * 0x33 + 0x77) & 0xFF;
            pc = XD_FILL_INC;
        } else if (pc == XD_FILL_INC) {
            idx = idx + 1;
            pc = XD_FILL_CHECK;
        } else if (pc == XD_INIT_DEC) {
            idx = 0;
            pc = XD_DEC_CHECK;
        } else if (pc == XD_DEC_CHECK) {
            pc = (idx < 8) ? XD_DEC_LOAD : XD_INIT_SUM;
        } else if (pc == XD_DEC_LOAD) {
            byte = buf[idx];
            pc = XD_DEC_KEY;
        } else if (pc == XD_DEC_KEY) {
            subkey = (key + idx) & 0xFF;
            pc = XD_DEC_STORE;
        } else if (pc == XD_DEC_STORE) {
            buf[idx] = byte ^ subkey;
            pc = XD_DEC_INC;
        } else if (pc == XD_DEC_INC) {
            idx = idx + 1;
            pc = XD_DEC_CHECK;
        } else if (pc == XD_INIT_SUM) {
            idx = 0;
            pc = XD_SUM_CHECK;
        } else if (pc == XD_SUM_CHECK) {
            pc = (idx < 8) ? XD_SUM_BODY : XD_HALT;
        } else if (pc == XD_SUM_BODY) {
            sum = sum + buf[idx];
            pc = XD_SUM_INC;
        } else if (pc == XD_SUM_INC) {
            idx = idx + 1;
            pc = XD_SUM_CHECK;
        } else if (pc == XD_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_xordecrypt_loop(0x55)=%d vm_xordecrypt_loop(0x7F)=%d\n",
           vm_xordecrypt_loop_target(0x55), vm_xordecrypt_loop_target(0x7F));
    return 0;
}
