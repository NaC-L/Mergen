/* PC-state VM running an FNV-1 (NOT FNV-1a) hash chain at u16 word
 * stride over n = (x & 3) + 1 words:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0xCBF29CE484222325;            // FNV offset basis
 *   for (i = 0; i < n; i++) {
 *     r = (r * 0x100000001B3) ^ (s & 0xFFFF);  // mul-then-xor (FNV-1)
 *     s = s >> 16;
 *   }
 *   return r;
 *
 * Lift target: vm_fnv1_word64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a_word64_loop (sister: r = (r ^ w) * prime instead of (r * prime) ^ w)
 *   - vm_fnv164_loop       (byte-stride FNV-1)
 *
 * Same FNV prime/offset basis with mul-then-xor op order at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum F1wVmPc {
    F1W_INIT_ALL = 0,
    F1W_CHECK    = 1,
    F1W_HASH     = 2,
    F1W_SHIFT    = 3,
    F1W_INC      = 4,
    F1W_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_fnv1_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = F1W_INIT_ALL;

    while (1) {
        if (pc == F1W_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0xCBF29CE484222325ull;
            i = 0ull;
            pc = F1W_CHECK;
        } else if (pc == F1W_CHECK) {
            pc = (i < n) ? F1W_HASH : F1W_HALT;
        } else if (pc == F1W_HASH) {
            r = (r * 0x100000001B3ull) ^ (s & 0xFFFFull);
            pc = F1W_SHIFT;
        } else if (pc == F1W_SHIFT) {
            s = s >> 16;
            pc = F1W_INC;
        } else if (pc == F1W_INC) {
            i = i + 1ull;
            pc = F1W_CHECK;
        } else if (pc == F1W_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fnv1_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fnv1_word64_loop_target(0xCAFEBABEull));
    return 0;
}
