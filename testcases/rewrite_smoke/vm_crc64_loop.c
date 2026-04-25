/* PC-state VM running an i64 CRC-64-style polynomial reduction step.
 *   crc = x | 1;
 *   for i in 0..n:
 *     if (crc & 1): crc = (crc >> 1) ^ POLY
 *     else:         crc = (crc >> 1)
 * Variable trip n = (x & 7) + 1.  POLY = 0xC96C5795D7870F42 (CRC-64 ISO).
 * Lift target: vm_crc64_loop_target.
 *
 * Distinct from vm_lfsr64_loop (4-tap feedback) and vm_pcg64_loop
 * (LCG step): single-tap conditional XOR gated by LSB, classic CRC
 * polynomial reduction shape.
 */
#include <stdio.h>
#include <stdint.h>

enum CrVmPc {
    CR_LOAD       = 0,
    CR_INIT       = 1,
    CR_LOOP_CHECK = 2,
    CR_LOOP_BODY  = 3,
    CR_LOOP_INC   = 4,
    CR_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_crc64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t crc = 0;
    int      pc  = CR_LOAD;

    while (1) {
        if (pc == CR_LOAD) {
            crc = x | 1ull;
            n   = (int)(x & 7ull) + 1;
            pc = CR_INIT;
        } else if (pc == CR_INIT) {
            idx = 0;
            pc = CR_LOOP_CHECK;
        } else if (pc == CR_LOOP_CHECK) {
            pc = (idx < n) ? CR_LOOP_BODY : CR_HALT;
        } else if (pc == CR_LOOP_BODY) {
            if ((crc & 1ull) != 0ull) {
                crc = (crc >> 1) ^ 0xC96C5795D7870F42ull;
            } else {
                crc = crc >> 1;
            }
            pc = CR_LOOP_INC;
        } else if (pc == CR_LOOP_INC) {
            idx = idx + 1;
            pc = CR_LOOP_CHECK;
        } else if (pc == CR_HALT) {
            return crc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_crc64(0xCAFE)=%llu vm_crc64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_crc64_loop_target(0xCAFEull),
           (unsigned long long)vm_crc64_loop_target(0xDEADBEEFull));
    return 0;
}
