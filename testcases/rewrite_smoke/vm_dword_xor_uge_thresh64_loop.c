/* PC-state VM that XOR-accumulates u32 dwords >= 0x80000000:
 *
 *   n = (x & 1) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     acc = acc ^ ((d >= 0x80000000) ? d : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_dword_xor_uge_thresh64_loop_target.
 *
 * Predicate-gated XOR accumulator at u32 stride.  Dword counterpart
 * of vm_byte/word_xor_uge_thresh64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum DxsVmPc {
    DXS_INIT_ALL = 0,
    DXS_CHECK    = 1,
    DXS_BODY     = 2,
    DXS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_xor_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = DXS_INIT_ALL;

    while (1) {
        if (pc == DXS_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = DXS_CHECK;
        } else if (pc == DXS_CHECK) {
            pc = (n > 0ull) ? DXS_BODY : DXS_HALT;
        } else if (pc == DXS_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            acc = acc ^ ((d >= 0x80000000ull) ? d : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DXS_CHECK;
        } else if (pc == DXS_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_xor_uge_thresh64(0x800000017FFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_xor_uge_thresh64_loop_target(0x800000017FFFFFFFull));
    return 0;
}
