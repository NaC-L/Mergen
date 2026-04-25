/* PC-state VM that fills a 3x3 stack grid via nested loops, then sums
 * the main and anti diagonals.
 * Lift target: vm_2d_loop_target.
 * Goal: cover 2D-style indexing (grid[i][j] flattens to grid[i*3+j]) with
 * nested PC-state loops, and a tail compute that pulls fixed-offset
 * elements from the same array.
 */
#include <stdio.h>

enum TdVmPc {
    TD_LOAD       = 0,
    TD_OUTER_INIT = 1,
    TD_OUTER_CHECK = 2,
    TD_INNER_INIT = 3,
    TD_INNER_CHECK = 4,
    TD_FILL_BODY  = 5,
    TD_INNER_INC  = 6,
    TD_OUTER_INC  = 7,
    TD_DIAG       = 8,
    TD_ANTI       = 9,
    TD_PACK       = 10,
    TD_HALT       = 11,
};

__declspec(noinline)
int vm_2d_loop_target(int x) {
    int grid[9];
    int seed = 0;
    int i    = 0;
    int j    = 0;
    int diag = 0;
    int anti = 0;
    int result = 0;
    int pc   = TD_LOAD;

    while (1) {
        if (pc == TD_LOAD) {
            seed = x & 0xF;
            pc = TD_OUTER_INIT;
        } else if (pc == TD_OUTER_INIT) {
            i = 0;
            pc = TD_OUTER_CHECK;
        } else if (pc == TD_OUTER_CHECK) {
            pc = (i < 3) ? TD_INNER_INIT : TD_DIAG;
        } else if (pc == TD_INNER_INIT) {
            j = 0;
            pc = TD_INNER_CHECK;
        } else if (pc == TD_INNER_CHECK) {
            pc = (j < 3) ? TD_FILL_BODY : TD_OUTER_INC;
        } else if (pc == TD_FILL_BODY) {
            grid[i * 3 + j] = (i * 3 + j + seed) & 0x1F;
            pc = TD_INNER_INC;
        } else if (pc == TD_INNER_INC) {
            j = j + 1;
            pc = TD_INNER_CHECK;
        } else if (pc == TD_OUTER_INC) {
            i = i + 1;
            pc = TD_OUTER_CHECK;
        } else if (pc == TD_DIAG) {
            diag = grid[0] + grid[4] + grid[8];
            pc = TD_ANTI;
        } else if (pc == TD_ANTI) {
            anti = grid[2] + grid[4] + grid[6];
            pc = TD_PACK;
        } else if (pc == TD_PACK) {
            result = diag * 100 + anti;
            pc = TD_HALT;
        } else if (pc == TD_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_2d_loop(0xA)=%d vm_2d_loop(0xCAFE)=%d\n",
           vm_2d_loop_target(0xA),
           vm_2d_loop_target(0xCAFE));
    return 0;
}
