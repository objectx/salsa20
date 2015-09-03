#include <cstdint>
#include <array>
#include <catch/catch.hpp>

#ifdef HAVE_SSE3

#include <xmmintrin.h>

using expect_t = std::array<int32_t, 16> ;

static bool check (__m128i a0, __m128i a1, __m128i a2, __m128i a3, const expect_t &expect) {
    uint32_t actual [4 * 4] __attribute__ ((__aligned__ (32))) ;

    _mm_store_si128 ((__m128i *)&actual [ 0], a0) ;
    _mm_store_si128 ((__m128i *)&actual [ 4], a1) ;
    _mm_store_si128 ((__m128i *)&actual [ 8], a2) ;
    _mm_store_si128 ((__m128i *)&actual [12], a3) ;

    for (int_fast32_t i = 0 ; i < expect.size () ; ++i) {
        if (actual [i] != expect [i]) {
            return false ;
        }
    }
    return true ;
}

#define CHK_(V_, e0_, e1_, e2_, e3_)    do {            \
    uint32_t a_ [4] __attribute__ ((__aligned__ (32))) ;\
    _mm_store_si128 ((__m128i *)&a_ [0], (V_)) ;        \
    REQUIRE (a_ [0] == (e0_)) ;                         \
    REQUIRE (a_ [1] == (e1_)) ;                         \
    REQUIRE (a_ [2] == (e2_)) ;                         \
    REQUIRE (a_ [3] == (e3_)) ;                         \
} while (false)


#define SWAP_(a_, b_)   do {        \
        __m128i     t_ = (a_) ;     \
        (a_) = (b_) ;               \
        (b_) = t_ ;                 \
    } while (false)

#define TRANSPOSE_(V0_, V1_, V2_, V3_) do {                 \
        __m128i t0_ = _mm_unpacklo_epi32 ((V0_), (V1_)) ;   \
        __m128i t1_ = _mm_unpacklo_epi32 ((V2_), (V3_)) ;   \
        __m128i t2_ = _mm_unpackhi_epi32 ((V0_), (V1_)) ;   \
        __m128i t3_ = _mm_unpackhi_epi32 ((V2_), (V3_)) ;   \
        (V0_) = _mm_unpacklo_epi64 (t0_, t1_) ;             \
        (V1_) = _mm_unpackhi_epi64 (t0_, t1_) ;             \
        (V2_) = _mm_unpacklo_epi64 (t2_, t3_) ;             \
        (V3_) = _mm_unpackhi_epi64 (t2_, t3_) ;             \
    } while (false)


TEST_CASE ("SSE test", "[sse]") {
    __m128i v0 = _mm_set_epi32 ( 3,  2,  1,  0) ;
    __m128i v1 = _mm_set_epi32 ( 7,  6,  5,  4) ;
    __m128i v2 = _mm_set_epi32 (11, 10,  9,  8) ;
    __m128i v3 = _mm_set_epi32 (15, 14, 13, 12) ;

    CHK_ (v0,  0,  1,  2,  3) ;
    CHK_ (v1,  4,  5,  6,  7) ;
    CHK_ (v2,  8,  9, 10, 11) ;
    CHK_ (v3, 12, 13, 14, 15) ;
    SECTION ("Shuffle") {
        v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (0, 3, 2, 1));
        v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2));
        v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (2, 1, 0, 3));
        CHK_ (v0,  0,  1,  2,  3) ;
        CHK_ (v1,  5,  6,  7,  4) ;
        CHK_ (v2, 10, 11,  8,  9) ;
        CHK_ (v3, 15, 12, 13, 14) ;
    SECTION ("Transpose") {
        TRANSPOSE_ (v0, v1, v2, v3) ;
        CHK_ (v0, 0,  5, 10, 15) ;
        CHK_ (v1, 1,  6, 11, 12) ;
        CHK_ (v2, 2,  7,  8, 13) ;
        CHK_ (v3, 3,  4,  9, 14) ;
    SECTION ("Swap") {
        SWAP_ (v1, v3) ;
        CHK_ (v0, 0, 5, 10, 15) ;
        CHK_ (v1, 3, 4,  9, 14) ;
        CHK_ (v2, 2, 7,  8, 13) ;
        CHK_ (v3, 1, 6, 11, 12) ;
    SECTION ("Permute") {
        v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (0, 3, 2, 1)) ;
        v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
        v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (2, 1, 0, 3)) ;
        CHK_ (v0,  0,  5, 10, 15) ;
        CHK_ (v1,  4,  9, 14,  3) ;
        CHK_ (v2,  8, 13,  2,  7) ;
        CHK_ (v3, 12,  1,  6, 11) ;
    SECTION ("Permute 2") {
        v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (2, 1, 0, 3)) ;
        v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
        v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (0, 3, 2, 1)) ;
        CHK_ (v0, 0, 5, 10, 15) ;
        CHK_ (v1, 3, 4,  9, 14) ;
        CHK_ (v2, 2, 7,  8, 13) ;
        CHK_ (v3, 1, 6, 11, 12) ;
    SECTION ("Transpose 2") {
        TRANSPOSE_ (v0, v1, v2, v3) ;
        CHK_ (v0,  0,  3,  2,  1) ;
        CHK_ (v1,  5,  4,  7,  6) ;
        CHK_ (v2, 10,  9,  8, 11) ;
        CHK_ (v3, 15, 14, 13, 12) ;
    SECTION ("Permute 3") {
        v0 = _mm_shuffle_epi32 (v0, _MM_SHUFFLE (1, 2, 3, 0)) ;
        v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (2, 3, 0, 1)) ;
        v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (3, 0, 1, 2)) ;
        v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (0, 1, 2, 3)) ;
        CHK_ (v0,  0,  1,  2,  3) ;
        CHK_ (v1,  4,  5,  6,  7) ;
        CHK_ (v2,  8,  9, 10, 11) ;
        CHK_ (v3, 12, 13, 14, 15) ;
    }}}}}}}
}

#endif
