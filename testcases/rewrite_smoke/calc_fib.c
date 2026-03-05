/* Iterative Fibonacci with constant bound.
 * Lift target: calc_fib — concrete loop (7 iterations), stack variables.
 * fib(7) = 13.  Concolic engine should unroll; LLVM folds to constant.
 * This is the first test of real compiler-generated /Od loop code. */
#include <stdio.h>

__declspec(noinline)
int calc_fib(void) {
    int a = 0, b = 1;
    for (int i = 0; i < 7; i++) {
        int t = a + b;
        a = b;
        b = t;
    }
    return a;
}

int main(void) {
    printf("fib(7)=%d\n", calc_fib());
    return 0;
}
