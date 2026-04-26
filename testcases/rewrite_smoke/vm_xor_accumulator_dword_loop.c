/* PC-state VM accumulating XOR of i*k for i in 0..1, where k = x & 0xFFFFFFFF.
 * Lift target: vm_xor_accumulator_dword_loop_target.
 *
 * Distinct from:
 *   - vm_xor_accumulator_word_loop (4-trip, u16 key)
 *   - vm_xor_accumulator_loop      (8-trip, u8 key)
 *
 * Fixed 2-trip loop body uses multiplication and XOR (not add) into
 * the accumulator with a u32 dword-derived symbolic key.  Trip count
 * is small but the lifter cannot collapse the XOR accumulator to a
 * constant because the key is symbolic.
 */
#include <stdio.h>

__declspec(noinline)
unsigned vm_xor_accumulator_dword_loop_target(unsigned x) {
    unsigned key  = 0;
    unsigned acc  = 0;
    unsigned idx  = 0;
    unsigned prod = 0;
    int pc   = 0;

    while (1) {
        if (pc == 0) {
            pc = 1;
        } else if (pc == 1) {
            key = x;
            pc = 2;
        } else if (pc == 2) {
            acc = 0;
            pc = 3;
        } else if (pc == 3) {
            idx = 0;
            pc = 4;
        } else if (pc == 4) {
            pc = (idx < 2) ? 5 : 8;
        } else if (pc == 5) {
            prod = idx * key;
            pc = 6;
        } else if (pc == 6) {
            acc = acc ^ prod;
            pc = 7;
        } else if (pc == 7) {
            idx = idx + 1;
            pc = 4;
        } else if (pc == 8) {
            return acc;
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_xor_accumulator_dword_loop(0xCAFEBABE)=%u\n",
           (unsigned)vm_xor_accumulator_dword_loop_target(0xCAFEBABEu));
    return 0;
}
