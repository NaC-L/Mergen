/* PC-state VM whose body calls __builtin_bswap32 (lowered by clang to
 * @llvm.bswap.i32) on x XOR'd with a per-iteration shift constant.
 * Lift target: vm_imported_bswap_loop_target.
 * Goal: cover a fourth recognized-intrinsic shape.  bswap exercises the
 * lifter's byte-permutation lowering inside a VM dispatcher.
 */
#include <stdio.h>

enum BwVmPc {
    BW_LOAD       = 0,
    BW_INIT       = 1,
    BW_CHECK      = 2,
    BW_BODY_XOR   = 3,
    BW_BODY_CALL  = 4,
    BW_BODY_ADD   = 5,
    BW_BODY_INC   = 6,
    BW_HALT       = 7,
};

__declspec(noinline)
int vm_imported_bswap_loop_target(int x) {
    unsigned limit = 0;
    unsigned idx   = 0;
    unsigned sum   = 0;
    unsigned v     = 0;
    unsigned bs    = 0;
    int pc         = BW_LOAD;

    while (1) {
        if (pc == BW_LOAD) {
            limit = ((unsigned)x & 7) + 1;
            sum = 0;
            pc = BW_INIT;
        } else if (pc == BW_INIT) {
            idx = 0;
            pc = BW_CHECK;
        } else if (pc == BW_CHECK) {
            pc = (idx < limit) ? BW_BODY_XOR : BW_HALT;
        } else if (pc == BW_BODY_XOR) {
            v = (unsigned)x ^ ((idx + 1) << 24);
            pc = BW_BODY_CALL;
        } else if (pc == BW_BODY_CALL) {
            bs = __builtin_bswap32(v);
            pc = BW_BODY_ADD;
        } else if (pc == BW_BODY_ADD) {
            sum = sum + bs;
            pc = BW_BODY_INC;
        } else if (pc == BW_BODY_INC) {
            idx = idx + 1;
            pc = BW_CHECK;
        } else if (pc == BW_HALT) {
            return (int)sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_bswap_loop(0xDEADBEEF)=%u vm_imported_bswap_loop(0xFF)=%u\n",
           (unsigned)vm_imported_bswap_loop_target((int)0xDEADBEEFu),
           (unsigned)vm_imported_bswap_loop_target(0xFF));
    return 0;
}
