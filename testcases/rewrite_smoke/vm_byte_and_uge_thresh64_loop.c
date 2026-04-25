/* PC-state VM that AND-accumulates bytes whose value is >= 0x80
 * (default 0xFF acts as the AND-identity when the predicate is false):
 *
 *   n = (x & 7) + 1;
 *   s = x; acc = 0xFF;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     acc = acc & ((b >= 0x80) ? b : 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_byte_and_uge_thresh64_loop_target.
 *
 * Predicate-gated AND accumulator at byte stride.  Distinct from the
 * add/xor/or siblings because the false-branch identity is 0xFF, not 0.
 */
#include <stdio.h>
#include <stdint.h>

enum BandVmPc {
    BAND_INIT_ALL = 0,
    BAND_CHECK    = 1,
    BAND_BODY     = 2,
    BAND_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_and_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = BAND_INIT_ALL;

    while (1) {
        if (pc == BAND_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            acc = 0xFFull;
            pc = BAND_CHECK;
        } else if (pc == BAND_CHECK) {
            pc = (n > 0ull) ? BAND_BODY : BAND_HALT;
        } else if (pc == BAND_BODY) {
            uint64_t b = s & 0xFFull;
            acc = acc & ((b >= 0x80ull) ? b : 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = BAND_CHECK;
        } else if (pc == BAND_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_and_uge_thresh64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byte_and_uge_thresh64_loop_target(0xCAFEBABEull));
    return 0;
}
