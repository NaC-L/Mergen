/* PC-state VM that computes a dword-wise PREFIX-XOR scan on the u32
 * dwords of x and packs the running results back into a uint64_t.
 *   result = 0; acc = 0;
 *   for i in 0..2:
 *     d = (x >> (i*32)) & 0xFFFFFFFF
 *     acc ^= d
 *     result |= (acc << (i*32))
 *   return result;
 * 2-trip fixed loop with dword-walking shift on both load and pack.
 * Lift target: vm_prefixxor_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_prefixxor_word64_loop (16-bit stride 4-trip)
 *   - vm_prefixxor64_loop      (8-bit stride 8-trip)
 *   - vm_xordwords64_loop      (2-trip XOR-fold to single u32)
 *
 * Tests two simultaneous u32 dword-walking shifts at u32 stride.
 * After 2 trips the high dword of result is the XOR of the two input
 * dwords; the low dword is the input low dword unchanged.
 */
#include <stdio.h>
#include <stdint.h>

enum PfdVmPc {
    PFD_LOAD       = 0,
    PFD_INIT       = 1,
    PFD_LOOP_CHECK = 2,
    PFD_LOOP_BODY  = 3,
    PFD_LOOP_INC   = 4,
    PFD_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_prefixxor_dword64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t acc    = 0;
    uint64_t result = 0;
    int      pc     = PFD_LOAD;

    while (1) {
        if (pc == PFD_LOAD) {
            xx     = x;
            acc    = 0ull;
            result = 0ull;
            pc = PFD_INIT;
        } else if (pc == PFD_INIT) {
            idx = 0;
            pc = PFD_LOOP_CHECK;
        } else if (pc == PFD_LOOP_CHECK) {
            pc = (idx < 2) ? PFD_LOOP_BODY : PFD_HALT;
        } else if (pc == PFD_LOOP_BODY) {
            uint64_t d = (xx >> (idx * 32)) & 0xFFFFFFFFull;
            acc = acc ^ d;
            result = result | (acc << (idx * 32));
            pc = PFD_LOOP_INC;
        } else if (pc == PFD_LOOP_INC) {
            idx = idx + 1;
            pc = PFD_LOOP_CHECK;
        } else if (pc == PFD_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_prefixxor_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_prefixxor_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
