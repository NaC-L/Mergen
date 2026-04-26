/* PC-state VM running a djb2a-style (XOR variant) hash chain over
 * n = (x & 1) + 1 u32 dwords:
 *
 *   n = (x & 1) + 1;
 *   xx = x; h = 5381;
 *   for (idx = 0; idx < n; idx++) {
 *     uint64_t d = (xx >> (idx * 32)) & 0xFFFFFFFF;
 *     h = h * 33 ^ d;
 *   }
 *   return h;
 *
 * Lift target: vm_djb2a_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_djb2_dword64_loop (sister: h = h*33 + d instead of h = h*33 ^ d)
 *   - vm_djb2a64_loop      (byte-stride djb2a)
 *   - vm_djb2a_word64_loop (word-stride djb2a)
 *
 * Tests `mul i64 r, 33` followed by `xor lane` at u32 stride, starting
 * from the djb2 offset basis 5381.
 */
#include <stdio.h>
#include <stdint.h>

enum DjadVmPc {
    DJAD_LOAD       = 0,
    DJAD_INIT       = 1,
    DJAD_LOOP_CHECK = 2,
    DJAD_LOOP_BODY  = 3,
    DJAD_LOOP_INC   = 4,
    DJAD_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_djb2a_dword64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t h   = 0;
    uint64_t xx  = 0;
    int      pc  = DJAD_LOAD;

    while (1) {
        if (pc == DJAD_LOAD) {
            n  = (int)(x & 1ull) + 1;
            xx = x;
            h  = 5381ull;
            pc = DJAD_INIT;
        } else if (pc == DJAD_INIT) {
            idx = 0;
            pc = DJAD_LOOP_CHECK;
        } else if (pc == DJAD_LOOP_CHECK) {
            pc = (idx < n) ? DJAD_LOOP_BODY : DJAD_HALT;
        } else if (pc == DJAD_LOOP_BODY) {
            uint64_t d = (xx >> (idx * 32)) & 0xFFFFFFFFull;
            h = h * 33ull ^ d;
            pc = DJAD_LOOP_INC;
        } else if (pc == DJAD_LOOP_INC) {
            idx = idx + 1;
            pc = DJAD_LOOP_CHECK;
        } else if (pc == DJAD_HALT) {
            return h;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_djb2a_dword64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_djb2a_dword64_loop_target(0xCAFEBABEull));
    return 0;
}
