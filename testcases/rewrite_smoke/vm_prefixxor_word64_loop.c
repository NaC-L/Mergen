/* PC-state VM that computes a word-wise PREFIX-XOR scan on the u16
 * words of x and packs the running results back into a uint64_t.
 *   result = 0; acc = 0;
 *   for i in 0..4:
 *     w = (x >> (i*16)) & 0xFFFF
 *     acc ^= w
 *     result |= (acc << (i*16))
 *   return result;
 * 4-trip fixed loop with word-walking shift on both load and pack
 * sides.  Lift target: vm_prefixxor_word64_loop_target.
 *
 * Distinct from:
 *   - vm_prefixxor64_loop (byte stride 8-trip)
 *   - vm_xorwords64_loop  (4-trip XOR-fold to single u16)
 *
 * Tests two simultaneous u16 word-walking shifts (one load, one
 * store-by-or) inside a single loop body.
 */
#include <stdio.h>
#include <stdint.h>

enum PfwVmPc {
    PFW_LOAD       = 0,
    PFW_INIT       = 1,
    PFW_LOOP_CHECK = 2,
    PFW_LOOP_BODY  = 3,
    PFW_LOOP_INC   = 4,
    PFW_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_prefixxor_word64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t acc    = 0;
    uint64_t result = 0;
    int      pc     = PFW_LOAD;

    while (1) {
        if (pc == PFW_LOAD) {
            xx     = x;
            acc    = 0ull;
            result = 0ull;
            pc = PFW_INIT;
        } else if (pc == PFW_INIT) {
            idx = 0;
            pc = PFW_LOOP_CHECK;
        } else if (pc == PFW_LOOP_CHECK) {
            pc = (idx < 4) ? PFW_LOOP_BODY : PFW_HALT;
        } else if (pc == PFW_LOOP_BODY) {
            uint64_t w = (xx >> (idx * 16)) & 0xFFFFull;
            acc = acc ^ w;
            result = result | (acc << (idx * 16));
            pc = PFW_LOOP_INC;
        } else if (pc == PFW_LOOP_INC) {
            idx = idx + 1;
            pc = PFW_LOOP_CHECK;
        } else if (pc == PFW_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_prefixxor_word64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_prefixxor_word64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
