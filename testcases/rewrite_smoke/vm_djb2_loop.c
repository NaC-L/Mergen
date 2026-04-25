/* PC-state VM running a DJB2-style hash recurrence:
 *   hash = (hash * 33 + nibble) & 0xFFFF
 * over the low (limit*4) bits of x.
 * Lift target: vm_djb2_loop_target.
 * Goal: cover a multiplicative-then-additive recurrence with symbolic input
 * shape (each iteration consumes a different nibble).  Distinct from
 * vm_lcg_loop (no per-iter input) and vm_polynomial_loop (constant
 * coefficient array).
 */
#include <stdio.h>

enum DjVmPc {
    DJ_LOAD       = 0,
    DJ_INIT       = 1,
    DJ_CHECK      = 2,
    DJ_BODY_NIB   = 3,
    DJ_BODY_MUL   = 4,
    DJ_BODY_ADD   = 5,
    DJ_BODY_INC   = 6,
    DJ_HALT       = 7,
};

__declspec(noinline)
int vm_djb2_loop_target(int x) {
    int hash  = 0;
    int limit = 0;
    int idx   = 0;
    int nib   = 0;
    int prod  = 0;
    int shift = 0;
    int pc    = DJ_LOAD;

    while (1) {
        if (pc == DJ_LOAD) {
            limit = (x & 7) + 1;
            hash = 5381;
            idx = 0;
            pc = DJ_INIT;
        } else if (pc == DJ_INIT) {
            pc = DJ_CHECK;
        } else if (pc == DJ_CHECK) {
            pc = (idx < limit) ? DJ_BODY_NIB : DJ_HALT;
        } else if (pc == DJ_BODY_NIB) {
            shift = idx * 4;
            nib = (x >> shift) & 0xF;
            pc = DJ_BODY_MUL;
        } else if (pc == DJ_BODY_MUL) {
            prod = hash * 33;
            pc = DJ_BODY_ADD;
        } else if (pc == DJ_BODY_ADD) {
            hash = (prod + nib) & 0xFFFF;
            pc = DJ_BODY_INC;
        } else if (pc == DJ_BODY_INC) {
            idx = idx + 1;
            pc = DJ_CHECK;
        } else if (pc == DJ_HALT) {
            return hash;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_djb2_loop(0x12345)=%d vm_djb2_loop(0xABCDEF)=%d\n",
           vm_djb2_loop_target(0x12345), vm_djb2_loop_target(0xABCDEF));
    return 0;
}
