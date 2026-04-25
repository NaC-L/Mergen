/* PC-state VM whose body calls _BitScanForward (MSVC intrinsic) inside the
 * dispatcher, accumulating the bit-position outputs.
 * Lift target: vm_imported_bsf_loop_target.
 * Goal: cover an intrinsic that returns its result via OUTPUT POINTER (the
 * unsigned long * arg).  Distinct from the previous direct-return
 * intrinsics because the lifter has to model both the call and the
 * subsequent stack-load that picks up the result.
 */
#include <stdio.h>
#include <intrin.h>

enum BfVmPc {
    BF_LOAD       = 0,
    BF_INIT       = 1,
    BF_CHECK      = 2,
    BF_BODY_VAL   = 3,
    BF_BODY_CALL  = 4,
    BF_BODY_TEST  = 5,
    BF_BODY_ADD   = 6,
    BF_BODY_INC   = 7,
    BF_HALT       = 8,
};

__declspec(noinline)
int vm_imported_bsf_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    unsigned v = 0;
    unsigned long bit_index = 0;
    unsigned char ok = 0;
    int pc    = BF_LOAD;

    while (1) {
        if (pc == BF_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = BF_INIT;
        } else if (pc == BF_INIT) {
            idx = 0;
            pc = BF_CHECK;
        } else if (pc == BF_CHECK) {
            pc = (idx < limit) ? BF_BODY_VAL : BF_HALT;
        } else if (pc == BF_BODY_VAL) {
            v = ((unsigned)x ^ (unsigned)(idx * 0x42));
            pc = BF_BODY_CALL;
        } else if (pc == BF_BODY_CALL) {
            ok = _BitScanForward(&bit_index, v);
            pc = BF_BODY_TEST;
        } else if (pc == BF_BODY_TEST) {
            if (ok) sum = sum + (int)bit_index;
            pc = BF_BODY_INC;
        } else if (pc == BF_BODY_INC) {
            idx = idx + 1;
            pc = BF_CHECK;
        } else if (pc == BF_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_bsf_loop(0xCAFE)=%d vm_imported_bsf_loop(0x84)=%d\n",
           vm_imported_bsf_loop_target(0xCAFE),
           vm_imported_bsf_loop_target(0x84));
    return 0;
}
