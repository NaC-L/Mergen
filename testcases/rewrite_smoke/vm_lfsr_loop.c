/* PC-state VM running an 8-bit Galois LFSR (PRNG-style bitwise recurrence).
 * Lift target: vm_lfsr_loop_target.
 * Goal: cover a loop whose body conditionally XORs a tap polynomial after a
 * shift, distinct from popcount (no XOR with constant) and bitreverse (no
 * conditional). Both seed and trip count are symbolic:
 *   seed = (x & 0xFF) | 1   (avoid zero state)
 *   n    = (x >> 8) & 0xF
 * Init dispatcher state pre-writes the loop variables (dual_counter pattern).
 */
#include <stdio.h>

enum LfsrVmPc {
    LF_INIT       = 0,
    LF_LOAD       = 1,
    LF_CHECK      = 2,
    LF_TEST_LSB   = 3,
    LF_BODY_XOR   = 4,
    LF_BODY_SHIFT = 5,
    LF_BODY_DEC   = 6,
    LF_HALT       = 7,
};

__declspec(noinline)
int vm_lfsr_loop_target(int x) {
    int state = 0;
    int n     = 0;
    int lsb   = 0;
    int pc    = LF_LOAD;

    while (1) {
        if (pc == LF_LOAD) {
            state = (x & 0xFF) | 1;
            n = (x >> 8) & 0xF;
            pc = LF_CHECK;
        } else if (pc == LF_CHECK) {
            pc = (n > 0) ? LF_TEST_LSB : LF_HALT;
        } else if (pc == LF_TEST_LSB) {
            lsb = state & 1;
            pc = (lsb != 0) ? LF_BODY_XOR : LF_BODY_SHIFT;
        } else if (pc == LF_BODY_XOR) {
            state = (int)((unsigned)state >> 1);
            state = (state ^ 0xB8) & 0xFF;
            pc = LF_BODY_DEC;
        } else if (pc == LF_BODY_SHIFT) {
            state = (int)((unsigned)state >> 1) & 0xFF;
            pc = LF_BODY_DEC;
        } else if (pc == LF_BODY_DEC) {
            n = n - 1;
            pc = LF_CHECK;
        } else if (pc == LF_HALT) {
            return state;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_lfsr_loop(0x500)=%d vm_lfsr_loop(0xFFF)=%d\n",
           vm_lfsr_loop_target(0x500), vm_lfsr_loop_target(0xFFF));
    return 0;
}
