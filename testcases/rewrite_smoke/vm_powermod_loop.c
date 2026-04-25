/* PC-state VM running square-and-multiply modular exponentiation.
 * Lift target: vm_powermod_loop_target.
 * Goal: cover a loop body that combines (a) bitwise extraction of the LSB,
 * (b) conditional multiply-and-mod, (c) right shift of the exponent, and
 * (d) self-multiplication (square) - all of which appear together in real
 * cryptographic VM handlers.  Both base and exponent are symbolic; modulus
 * is the small prime 13 to keep arithmetic small enough for lli.
 */
#include <stdio.h>

enum PmVmPc {
    PM_LOAD       = 0,
    PM_INIT_RES   = 1,
    PM_MOD_BASE   = 2,
    PM_CHECK      = 3,
    PM_TEST_BIT   = 4,
    PM_BODY_MUL   = 5,
    PM_SHIFT_EXP  = 6,
    PM_SQUARE     = 7,
    PM_HALT       = 8,
};

__declspec(noinline)
int vm_powermod_loop_target(int x) {
    int base   = 0;
    int exp    = 0;
    int result = 0;
    int bit    = 0;
    int pc     = PM_LOAD;

    while (1) {
        if (pc == PM_LOAD) {
            base = (x & 0xF) + 1;
            exp = (x >> 4) & 0xFF;
            pc = PM_INIT_RES;
        } else if (pc == PM_INIT_RES) {
            result = 1;
            pc = PM_MOD_BASE;
        } else if (pc == PM_MOD_BASE) {
            base = base % 13;
            pc = PM_CHECK;
        } else if (pc == PM_CHECK) {
            pc = (exp > 0) ? PM_TEST_BIT : PM_HALT;
        } else if (pc == PM_TEST_BIT) {
            bit = exp & 1;
            pc = (bit != 0) ? PM_BODY_MUL : PM_SHIFT_EXP;
        } else if (pc == PM_BODY_MUL) {
            result = (result * base) % 13;
            pc = PM_SHIFT_EXP;
        } else if (pc == PM_SHIFT_EXP) {
            exp = (int)((unsigned)exp >> 1);
            pc = PM_SQUARE;
        } else if (pc == PM_SQUARE) {
            base = (base * base) % 13;
            pc = PM_CHECK;
        } else if (pc == PM_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_powermod_loop(0x53)=%d vm_powermod_loop(0x456)=%d\n",
           vm_powermod_loop_target(0x53), vm_powermod_loop_target(0x456));
    return 0;
}
