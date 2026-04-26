/* PC-state VM running a djb2-style hash chain over n = (x & 3) + 1
 * u16 words (canonical djb2 is byte-oriented; this is the wider-lane
 * variant for testing the lifter's mul-by-33 + add chain at u16
 * stride):
 *
 *   n = (x & 3) + 1;
 *   xx = x; h = 5381;
 *   for (idx = 0; idx < n; idx++) {
 *     uint64_t w = (xx >> (idx * 16)) & 0xFFFF;
 *     h = h * 33 + w;
 *   }
 *   return h;
 *
 * Lift target: vm_djb2_word64_loop_target.
 *
 * Distinct from:
 *   - vm_djb264_loop  (byte-stride canonical djb2)
 *   - vm_word_addchain64_loop (no multiplier, just add)
 *   - vm_word_horner13_64_loop (different multiplier and starting basis)
 *
 * Tests `mul i64 r, 33` followed by `add lane` at u16 stride, starting
 * from the djb2 offset basis 5381.
 */
#include <stdio.h>
#include <stdint.h>

enum DjwVmPc {
    DJW_LOAD       = 0,
    DJW_INIT       = 1,
    DJW_LOOP_CHECK = 2,
    DJW_LOOP_BODY  = 3,
    DJW_LOOP_INC   = 4,
    DJW_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_djb2_word64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t h   = 0;
    uint64_t xx  = 0;
    int      pc  = DJW_LOAD;

    while (1) {
        if (pc == DJW_LOAD) {
            n  = (int)(x & 3ull) + 1;
            xx = x;
            h  = 5381ull;
            pc = DJW_INIT;
        } else if (pc == DJW_INIT) {
            idx = 0;
            pc = DJW_LOOP_CHECK;
        } else if (pc == DJW_LOOP_CHECK) {
            pc = (idx < n) ? DJW_LOOP_BODY : DJW_HALT;
        } else if (pc == DJW_LOOP_BODY) {
            uint64_t w = (xx >> (idx * 16)) & 0xFFFFull;
            h = h * 33ull + w;
            pc = DJW_LOOP_INC;
        } else if (pc == DJW_LOOP_INC) {
            idx = idx + 1;
            pc = DJW_LOOP_CHECK;
        } else if (pc == DJW_HALT) {
            return h;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_djb2_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_djb2_word64_loop_target(0xCAFEBABEull));
    return 0;
}
