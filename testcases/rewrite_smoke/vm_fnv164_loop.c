/* PC-state VM running an FNV-1 (NOT FNV-1a) hash chain over n = (x & 7) + 1 bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xCBF29CE484222325;            // FNV offset basis
 *   for (i = 0; i < n; i++) {
 *     r = (r * 0x100000001B3) ^ (s & 0xFF);    // mul-then-xor (FNV-1)
 *     s = s >> 8;
 *   }
 *   return r;
 *
 * Lift target: vm_fnv164_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a64_loop  (sister: r = (r ^ b) * prime instead of (r * prime) ^ b)
 *
 * Same FNV prime/offset basis and per-byte loop, but op order swapped:
 * multiply by prime first, then XOR with the byte.  Tests the lifter's
 * mul/xor chain ordering across live state.
 */
#include <stdio.h>
#include <stdint.h>

enum F1VmPc {
    F1_INIT_ALL = 0,
    F1_CHECK    = 1,
    F1_HASH     = 2,
    F1_SHIFT    = 3,
    F1_INC      = 4,
    F1_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_fnv164_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = F1_INIT_ALL;

    while (1) {
        if (pc == F1_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xCBF29CE484222325ull;
            i = 0ull;
            pc = F1_CHECK;
        } else if (pc == F1_CHECK) {
            pc = (i < n) ? F1_HASH : F1_HALT;
        } else if (pc == F1_HASH) {
            r = (r * 0x100000001B3ull) ^ (s & 0xFFull);
            pc = F1_SHIFT;
        } else if (pc == F1_SHIFT) {
            s = s >> 8;
            pc = F1_INC;
        } else if (pc == F1_INC) {
            i = i + 1ull;
            pc = F1_CHECK;
        } else if (pc == F1_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fnv164(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_fnv164_loop_target(0xCAFEBABEull));
    return 0;
}
