/* PC-state VM running a djb2-style hash chain over n = (x & 1) + 1
 * u32 dwords (canonical djb2 is byte-oriented; this is the wider-lane
 * variant for testing the lifter's mul-by-33 + add chain at u32
 * stride):
 *
 *   n = (x & 1) + 1;
 *   xx = x; h = 5381;
 *   for (idx = 0; idx < n; idx++) {
 *     uint64_t d = (xx >> (idx * 32)) & 0xFFFFFFFF;
 *     h = h * 33 + d;
 *   }
 *   return h;
 *
 * Lift target: vm_djb2_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_djb2_word64_loop (16-bit lane stride)
 *   - vm_djb264_loop      (byte-stride canonical djb2)
 *   - vm_dword_horner7_64_loop (different multiplier and starting basis)
 *
 * Tests `mul i64 r, 33` followed by `add lane` at u32 stride, starting
 * from the djb2 offset basis 5381.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DjdVmPc {
    DJD_LOAD       = 0,
    DJD_INIT       = 1,
    DJD_LOOP_CHECK = 2,
    DJD_LOOP_BODY  = 3,
    DJD_LOOP_INC   = 4,
    DJD_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_djb2_dword64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t h   = 0;
    uint64_t xx  = 0;
    int      pc  = DJD_LOAD;

    while (1) {
        if (pc == DJD_LOAD) {
            n  = (int)(x & 1ull) + 1;
            xx = x;
            h  = 5381ull;
            pc = DJD_INIT;
        } else if (pc == DJD_INIT) {
            idx = 0;
            pc = DJD_LOOP_CHECK;
        } else if (pc == DJD_LOOP_CHECK) {
            pc = (idx < n) ? DJD_LOOP_BODY : DJD_HALT;
        } else if (pc == DJD_LOOP_BODY) {
            uint64_t d = (xx >> (idx * 32)) & 0xFFFFFFFFull;
            h = h * 33ull + d;
            pc = DJD_LOOP_INC;
        } else if (pc == DJD_LOOP_INC) {
            idx = idx + 1;
            pc = DJD_LOOP_CHECK;
        } else if (pc == DJD_HALT) {
            return h;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_djb2_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_djb2_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
