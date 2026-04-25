/* PC-state VM that XOR-accumulates u16 words >= 0x8000:
 *
 *   n = (x & 3) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     acc = acc ^ ((w >= 0x8000) ? w : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_word_xor_uge_thresh64_loop_target.
 *
 * Predicate-gated XOR accumulator at u16 stride.  Word counterpart
 * of vm_byte_xor_uge_thresh64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum WxsVmPc {
    WXS_INIT_ALL = 0,
    WXS_CHECK    = 1,
    WXS_BODY     = 2,
    WXS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_xor_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = WXS_INIT_ALL;

    while (1) {
        if (pc == WXS_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = WXS_CHECK;
        } else if (pc == WXS_CHECK) {
            pc = (n > 0ull) ? WXS_BODY : WXS_HALT;
        } else if (pc == WXS_BODY) {
            uint64_t w = s & 0xFFFFull;
            acc = acc ^ ((w >= 0x8000ull) ? w : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WXS_CHECK;
        } else if (pc == WXS_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_xor_uge_thresh64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_xor_uge_thresh64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
