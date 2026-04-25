/* PC-state VM that XOR-packs 2-bit chunks of x into r at DYNAMIC bit
 * positions controlled by the loop index:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0x3) << i);   // dynamic shl amount = i
 *     s >>= 2;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_pack64_loop_target.
 *
 * Distinct from vm_bitfetch_window64_loop (dynamic LSHR amount): this
 * sample exercises the complementary `shl i64 v, %i` where %i is the
 * loop-index phi.  Each iter's 2-bit chunk lands at a different bit
 * offset, so the lifter cannot fold the shift to a constant amount.
 * Combined with XOR accumulator and lshr-2 byte source.
 */
#include <stdio.h>
#include <stdint.h>

enum DsVmPc {
    DS_INIT_ALL = 0,
    DS_CHECK    = 1,
    DS_BODY     = 2,
    DS_INC      = 3,
    DS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynshl_pack64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DS_INIT_ALL;

    while (1) {
        if (pc == DS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DS_CHECK;
        } else if (pc == DS_CHECK) {
            pc = (i < n) ? DS_BODY : DS_HALT;
        } else if (pc == DS_BODY) {
            r = r ^ ((s & 0x3ull) << i);
            s = s >> 2;
            pc = DS_INC;
        } else if (pc == DS_INC) {
            i = i + 1ull;
            pc = DS_CHECK;
        } else if (pc == DS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynshl_pack64(0xFF)=%llu\n",
           (unsigned long long)vm_dynshl_pack64_loop_target(0xFFull));
    return 0;
}
