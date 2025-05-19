
#define PP_RSEQ_N() 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

#define PP_ARG_N(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14,  \
                 _15, _16, N, ...)                                             \
  N
#define PP_NARG_(...) PP_ARG_N(__VA_ARGS__)
#define PP_NARG(...) PP_NARG_(__VA_ARGS__, PP_RSEQ_N())

#define PP_PRIMITIVE_CAT(a, b) a##b
#define PP_CAT(a, b) PP_PRIMITIVE_CAT(a, b)
#define PP_FOREACH_0(MACRO, fn)
#define PP_FOREACH_1(MACRO, fn, A)
#define PP_FOREACH_2(MACRO, fn, A, B) MACRO(fn, A) MACRO(fn, B)
#define PP_FOREACH_3(MACRO, fn, A, B, C)                                       \
  PP_FOREACH_2(MACRO, fn, A, B) MACRO(fn, C)
#define PP_FOREACH_4(MACRO, fn, A, B, C, D)                                    \
  PP_FOREACH_3(MACRO, fn, A, B, C) MACRO(fn, D)
#define PP_FOREACH_5(MACRO, fn, A, B, C, D, E)                                 \
  PP_FOREACH_4(MACRO, fn, A, B, C, D) MACRO(fn, E)
#define PP_FOREACH_6(MACRO, fn, A, B, C, D, E, F)                              \
  PP_FOREACH_5(MACRO, fn, A, B, C, D, E) MACRO(fn, F)
#define PP_FOREACH_7(MACRO, fn, A, B, C, D, E, F, G)                           \
  PP_FOREACH_6(MACRO, fn, A, B, C, D, E, F) MACRO(fn, G)
#define PP_FOREACH_8(MACRO, fn, A, B, C, D, E, F, G, H)                        \
  PP_FOREACH_7(MACRO, fn, A, B, C, D, E, F, G) MACRO(fn, H)

#define PP_FOREACH_9(MACRO, fn, A, B, C, D, E, F, G, H, I)                     \
  PP_FOREACH_8(MACRO, fn, A, B, C, D, E, F, G, H) MACRO(fn, I)

#define PP_FOREACH_10(MACRO, fn, A, B, C, D, E, F, G, H, I, J)                 \
  PP_FOREACH_9(MACRO, fn, A, B, C, D, E, F, G, H, I) MACRO(fn, J)

#define PP_FOREACH_11(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K)              \
  PP_FOREACH_10(MACRO, fn, A, B, C, D, E, F, G, H, I, J) MACRO(fn, K)

#define PP_FOREACH_12(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L)           \
  PP_FOREACH_11(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K) MACRO(fn, L)

#define PP_FOREACH_13(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L, M)        \
  PP_FOREACH_12(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L) MACRO(fn, M)

#define PP_FOREACH_14(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L, M, N)     \
  PP_FOREACH_13(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L, M) MACRO(fn, N)

#define PP_FOREACH_15(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O)  \
  PP_FOREACH_14(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L, M, N)           \
  MACRO(fn, O)

#define PP_FOREACH_16(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O,  \
                      P)                                                       \
  PP_FOREACH_15(MACRO, fn, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O)        \
  MACRO(fn, P)

#define PP_FOREACH(M, fn, ...)                                                 \
  PP_CAT(PP_FOREACH_, PP_NARG(__VA_ARGS__))(M, fn, __VA_ARGS__)