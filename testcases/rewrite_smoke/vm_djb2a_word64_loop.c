/* PC-state VM running a djb2a-style (XOR variant) hash chain over
 * n = (x & 3) + 1 u16 words:
 *
 *   n = (x & 3) + 1;
 *   xx = x; h = 5381;
 *   for (idx = 0; idx < n; idx++) {
 *     uint64_t w = (xx >> (idx * 16)) & 0xFFFF;
 *     h = h * 33 ^ w;
 *   }
 *   return h;
 *
 * Lift target: vm_djb2a_word64_loop_target.
 *
 * Distinct from:
 *   - vm_djb2_word64_loop (sister: h = h*33 + w instead of h = h*33 ^ w)
 *   - vm_djb2a64_loop     (byte-stride djb2a)
 *
 * Tests `mul i64 r, 33` followed by `xor lane` at u16 stride, starting
 * from the djb2 offset basis 5381.
 */
#include <stdio.h>
#include <stdint.h>

enum DjawVmPc {
    DJAW_LOAD       = 0,
    DJAW_INIT       = 1,
    DJAW_LOOP_CHECK = 2,
    DJAW_LOOP_BODY  = 3,
    DJAW_LOOP_INC   = 4,
    DJAW_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_djb2a_word64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t h   = 0;
    uint64_t xx  = 0;
    int      pc  = DJAW_LOAD;

    while (1) {
        if (pc == DJAW_LOAD) {
            n  = (int)(x & 3ull) + 1;
            xx = x;
            h  = 5381ull;
            pc = DJAW_INIT;
        } else if (pc == DJAW_INIT) {
            idx = 0;
            pc = DJAW_LOOP_CHECK;
        } else if (pc == DJAW_LOOP_CHECK) {
            pc = (idx < n) ? DJAW_LOOP_BODY : DJAW_HALT;
        } else if (pc == DJAW_LOOP_BODY) {
            uint64_t w = (xx >> (idx * 16)) & 0xFFFFull;
            h = h * 33ull ^ w;
            pc = DJAW_LOOP_INC;
        } else if (pc == DJAW_LOOP_INC) {
            idx = idx + 1;
            pc = DJAW_LOOP_CHECK;
        } else if (pc == DJAW_HALT) {
            return h;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_djb2a_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_djb2a_word64_loop_target(0xCAFEBABEull));
    return 0;
}
