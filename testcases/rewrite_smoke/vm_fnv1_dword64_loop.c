/* PC-state VM running an FNV-1 (NOT FNV-1a) hash chain at u32 dword
 * stride over n = (x & 1) + 1 dwords:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0xCBF29CE484222325;            // FNV offset basis
 *   for (i = 0; i < n; i++) {
 *     r = (r * 0x100000001B3) ^ (s & 0xFFFFFFFF); // mul-then-xor (FNV-1)
 *     s = s >> 32;
 *   }
 *   return r;
 *
 * Lift target: vm_fnv1_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a_dword64_loop (sister: r = (r ^ d) * prime instead of (r * prime) ^ d)
 *   - vm_fnv164_loop        (byte-stride FNV-1)
 *   - vm_fnv1_word64_loop   (word-stride FNV-1)
 *
 * Same FNV prime/offset basis with mul-then-xor op order at u32 stride;
 * completes byte/word/dword coverage of FNV-1 paralleling FNV-1a.
 */
#include <stdio.h>
#include <stdint.h>

enum F1dVmPc {
    F1D_INIT_ALL = 0,
    F1D_CHECK    = 1,
    F1D_HASH     = 2,
    F1D_SHIFT    = 3,
    F1D_INC      = 4,
    F1D_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_fnv1_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = F1D_INIT_ALL;

    while (1) {
        if (pc == F1D_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0xCBF29CE484222325ull;
            i = 0ull;
            pc = F1D_CHECK;
        } else if (pc == F1D_CHECK) {
            pc = (i < n) ? F1D_HASH : F1D_HALT;
        } else if (pc == F1D_HASH) {
            r = (r * 0x100000001B3ull) ^ (s & 0xFFFFFFFFull);
            pc = F1D_SHIFT;
        } else if (pc == F1D_SHIFT) {
            s = s >> 32;
            pc = F1D_INC;
        } else if (pc == F1D_INC) {
            i = i + 1ull;
            pc = F1D_CHECK;
        } else if (pc == F1D_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fnv1_dword64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fnv1_dword64_loop_target(0xCAFEBABEull));
    return 0;
}
