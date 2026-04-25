/* PC-state VM running an i64 count-trailing-zeros via shift-loop.
 *   if (x == 0) return 64;
 *   count = 0;
 *   while ((x & 1) == 0) { x >>= 1; count++; }
 *   return count;
 * Variable trip count = ctz(x), bounded 0..63 (or short-circuit 64 for zero).
 * Lift target: vm_cttz64_loop_target.
 *
 * Distinct from vm_ctz_loop (i32) and vm_imported_cttz_loop (i32 _BitScanForward
 * intrinsic): exercises the same shape on full i64 with explicit shift-and-test
 * rather than the intrinsic.
 */
#include <stdio.h>
#include <stdint.h>

enum CzVmPc {
    CZ_LOAD       = 0,
    CZ_INIT       = 1,
    CZ_ZERO_CHECK = 2,
    CZ_LOOP_CHECK = 3,
    CZ_LOOP_BODY  = 4,
    CZ_HALT       = 5,
};

__declspec(noinline)
int vm_cttz64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = CZ_LOAD;

    while (1) {
        if (pc == CZ_LOAD) {
            state = x;
            count = 0;
            pc = CZ_ZERO_CHECK;
        } else if (pc == CZ_ZERO_CHECK) {
            if (state == 0ull) {
                count = 64;
                pc = CZ_HALT;
            } else {
                pc = CZ_LOOP_CHECK;
            }
        } else if (pc == CZ_LOOP_CHECK) {
            pc = ((state & 1ull) == 0ull) ? CZ_LOOP_BODY : CZ_HALT;
        } else if (pc == CZ_LOOP_BODY) {
            state = state >> 1;
            count = count + 1;
            pc = CZ_LOOP_CHECK;
        } else if (pc == CZ_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_cttz64(0x100000000)=%d vm_cttz64(0x8000000000000000)=%d\n",
           vm_cttz64_loop_target(0x100000000ull),
           vm_cttz64_loop_target(0x8000000000000000ull));
    return 0;
}
