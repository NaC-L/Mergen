/* PC-state VM that computes per-byte parity bit and packs the 8 parity
 * bits into the low byte of result.
 *   result = 0;
 *   for i in 0..8:
 *     byte = (x >> (i*8)) & 0xFF;
 *     // SWAR parity in three xor-shift steps:
 *     byte = (byte ^ (byte >> 4)) & 0xF;
 *     byte = (byte ^ (byte >> 2)) & 0x3;
 *     byte = (byte ^ (byte >> 1)) & 0x1;
 *     result |= byte << i;
 *   return result;
 * 8-trip fixed loop with three sequential xor-shift+mask steps inside.
 * Lift target: vm_byteparity64_loop_target.
 *
 * Distinct from vm_xorbytes64_loop (XOR-fold to single byte) and
 * vm_prefixxor64_loop (running prefix-XOR scan): per-byte SWAR parity
 * with 3 xor-shift+mask reductions in the inner body.
 */
#include <stdio.h>
#include <stdint.h>

enum BpVmPc {
    BP_LOAD       = 0,
    BP_INIT       = 1,
    BP_LOOP_CHECK = 2,
    BP_LOOP_BODY  = 3,
    BP_LOOP_INC   = 4,
    BP_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_byteparity64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t result = 0;
    int      pc     = BP_LOAD;

    while (1) {
        if (pc == BP_LOAD) {
            xx     = x;
            result = 0ull;
            pc = BP_INIT;
        } else if (pc == BP_INIT) {
            idx = 0;
            pc = BP_LOOP_CHECK;
        } else if (pc == BP_LOOP_CHECK) {
            pc = (idx < 8) ? BP_LOOP_BODY : BP_HALT;
        } else if (pc == BP_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            b = (b ^ (b >> 4)) & 0xFull;
            b = (b ^ (b >> 2)) & 0x3ull;
            b = (b ^ (b >> 1)) & 0x1ull;
            result = result | (b << idx);
            pc = BP_LOOP_INC;
        } else if (pc == BP_LOOP_INC) {
            idx = idx + 1;
            pc = BP_LOOP_CHECK;
        } else if (pc == BP_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteparity64(0xCAFEBABE)=%llu vm_byteparity64(0x0102030405060708)=%llu\n",
           (unsigned long long)vm_byteparity64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_byteparity64_loop_target(0x0102030405060708ull));
    return 0;
}
