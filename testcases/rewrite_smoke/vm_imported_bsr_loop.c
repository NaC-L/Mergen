/* PC-state VM whose body calls _BitScanReverse (MSVC intrinsic with output-
 * pointer arg) inside the dispatcher.
 * Lift target: vm_imported_bsr_loop_target.
 * Goal: cover the leading-zero counterpart to vm_imported_bsf_loop.  Both
 * MSVC bit-scan intrinsics use an output-pointer arg; this exercises the
 * other direction (high-bit position via 31 - clz).
 */
#include <stdio.h>
#include <intrin.h>

enum BrVmPc {
    BR_LOAD       = 0,
    BR_INIT       = 1,
    BR_CHECK      = 2,
    BR_BODY_VAL   = 3,
    BR_BODY_CALL  = 4,
    BR_BODY_TEST  = 5,
    BR_BODY_ADD   = 6,
    BR_BODY_INC   = 7,
    BR_HALT       = 8,
};

__declspec(noinline)
int vm_imported_bsr_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    unsigned v = 0;
    unsigned long bit_index = 0;
    unsigned char ok = 0;
    int pc    = BR_LOAD;

    while (1) {
        if (pc == BR_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = BR_INIT;
        } else if (pc == BR_INIT) {
            idx = 0;
            pc = BR_CHECK;
        } else if (pc == BR_CHECK) {
            pc = (idx < limit) ? BR_BODY_VAL : BR_HALT;
        } else if (pc == BR_BODY_VAL) {
            v = ((unsigned)x ^ (unsigned)(idx * 0x91));
            pc = BR_BODY_CALL;
        } else if (pc == BR_BODY_CALL) {
            ok = _BitScanReverse(&bit_index, v);
            pc = BR_BODY_TEST;
        } else if (pc == BR_BODY_TEST) {
            if (ok) sum = sum + (int)bit_index;
            pc = BR_BODY_INC;
        } else if (pc == BR_BODY_INC) {
            idx = idx + 1;
            pc = BR_CHECK;
        } else if (pc == BR_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_bsr_loop(0xCAFE)=%d vm_imported_bsr_loop(0xDEADBEEF)=%d\n",
           vm_imported_bsr_loop_target(0xCAFE),
           vm_imported_bsr_loop_target((int)0xDEADBEEFu));
    return 0;
}
