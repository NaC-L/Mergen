/* PC-state VM that computes a byte-wise PREFIX-XOR scan on the bytes of
 * x and packs the running results back into a uint64_t.
 *   result = 0; acc = 0;
 *   for i in 0..8:
 *     byte = (x >> (i*8)) & 0xFF
 *     acc ^= byte
 *     result |= (acc << (i*8))
 *   return result;
 * 8-trip fixed loop with byte-walking shift on both the input and the
 * pack side.  Lift target: vm_prefixxor64_loop_target.
 *
 * Distinct from vm_xorbytes64_loop (reduces to single byte) and
 * vm_djb264_loop (multiplicative byte hash): produces an 8-byte packed
 * running-XOR scan; tests two simultaneous byte-walking shifts (one
 * load, one store-by-or) inside a single loop body.
 */
#include <stdio.h>
#include <stdint.h>

enum PfVmPc {
    PF_LOAD       = 0,
    PF_INIT       = 1,
    PF_LOOP_CHECK = 2,
    PF_LOOP_BODY  = 3,
    PF_LOOP_INC   = 4,
    PF_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_prefixxor64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t acc    = 0;
    uint64_t result = 0;
    int      pc     = PF_LOAD;

    while (1) {
        if (pc == PF_LOAD) {
            xx     = x;
            acc    = 0ull;
            result = 0ull;
            pc = PF_INIT;
        } else if (pc == PF_INIT) {
            idx = 0;
            pc = PF_LOOP_CHECK;
        } else if (pc == PF_LOOP_CHECK) {
            pc = (idx < 8) ? PF_LOOP_BODY : PF_HALT;
        } else if (pc == PF_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            acc = acc ^ b;
            result = result | (acc << (idx * 8));
            pc = PF_LOOP_INC;
        } else if (pc == PF_LOOP_INC) {
            idx = idx + 1;
            pc = PF_LOOP_CHECK;
        } else if (pc == PF_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_prefixxor64(0xCAFEBABE)=%llu vm_prefixxor64(max)=%llu\n",
           (unsigned long long)vm_prefixxor64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_prefixxor64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
