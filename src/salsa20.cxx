/*
 * salsa20.cxx: The salsa20 cipher.
 *
 * AUTHOR(S): objectx
 *
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include "salsa20.h"

#if HAVE_CONFIG_H
#   include "config.h"
#endif

#ifdef HAVE_SSE3
#   include <xmmintrin.h>
#endif

static inline uint32_t ToInt32 (const void *start) {
#if defined (TARGET_ALLOWS_UNALIGNED_ACCESS) && defined (TARGET_LITTLE_ENDIAN)
    return *(static_cast<const uint32_t *> (start)) ;
#else
    auto p = static_cast<const uint8_t *> (start) ;

    return (  (static_cast<uint32_t> (p [0]) <<  0)
            | (static_cast<uint32_t> (p [1]) <<  8)
            | (static_cast<uint32_t> (p [2]) << 16)
            | (static_cast<uint32_t> (p [3]) << 24)) ;
#endif
}

static inline uint32_t  rot (uint32_t x, size_t n) {
#if defined (_MSC_VER) && (1200 <= _MSC_VER)
    return _rotl (x, n) ;
#else
    return(x << n) | (x >> (32 - n)) ;
#endif
}

#ifdef HAVE_SSE3

static inline __m128i   vrot (__m128i v, int cnt) {
    __m128i t0 = _mm_slli_epi32 (v, cnt) ;
    __m128i t1 = _mm_srli_epi32 (v, 32 - cnt) ;
    return _mm_or_si128 (t0, t1) ;
}

#endif
/* ------------------------------------------------------------------------ */

Salsa20::State::State () {
    ::memset (state_, 0, sizeof (state_)) ;
}

void    Salsa20::State::SetKey (const void *key, size_t key_size) {

    std::array<uint8_t, 32> K ;

    if (K.size () < key_size) {
        key_size = K.size () ;
    }

    K.fill (0) ;
    ::memcpy (&K [0], key, key_size) ;

    const uint32_t      mask = obfuscateMask_ ;

    if (key_size <= 16) {
        state_ [ 0] = tau_ [0] ^ mask ;

        state_ [ 1] = ToInt32 (&K [ 0]) ;
        state_ [ 2] = ToInt32 (&K [ 4]) ;
        state_ [ 3] = ToInt32 (&K [ 8]) ;
        state_ [ 4] = ToInt32 (&K [12]) ;

        state_ [ 5] = tau_ [1] ^ mask ;

        state_ [10] = tau_ [2] ^ mask ;

        state_ [11] = ToInt32 (&K [ 0]) ;
        state_ [12] = ToInt32 (&K [ 4]) ;
        state_ [13] = ToInt32 (&K [ 8]) ;
        state_ [14] = ToInt32 (&K [12]) ;

        state_ [15] = tau_ [3] ^ mask ;
    }
    else {
        state_ [ 0] = sigma_ [0] ^ mask ;

        state_ [ 1] = ToInt32 (&K [ 0]) ;
        state_ [ 2] = ToInt32 (&K [ 4]) ;
        state_ [ 3] = ToInt32 (&K [ 8]) ;
        state_ [ 4] = ToInt32 (&K [12]) ;

        state_ [ 5] = sigma_ [1] ^ mask ;

        state_ [10] = sigma_ [2] ^ mask ;

        state_ [11] = ToInt32 (&K [16]) ;
        state_ [12] = ToInt32 (&K [20]) ;
        state_ [13] = ToInt32 (&K [24]) ;
        state_ [14] = ToInt32 (&K [28]) ;

        state_ [15] = sigma_ [3] ^ mask ;
    }
    // Following 4 words are called "Nonce"...
    state_ [ 6] = 0 ; // Initial vector (lower 32bits)
    state_ [ 7] = 0 ; // Initial vector (upper 32bits)
    state_ [ 8] = 0 ; // Sequence (lower 32bits)
    state_ [ 9] = 0 ; // Sequence (upper 32bits)
}

void    Salsa20::State::SetInitialVector (uint64_t iv) {
    state_ [6] = static_cast<uint32_t> (iv >>  0) ;
    state_ [7] = static_cast<uint32_t> (iv >> 32) ;
    state_ [8] = 0 ;
    state_ [9] = 0 ;
}

uint64_t        Salsa20::State::GetSequenceNumber () const {
#if defined (TARGET_ALLOWS_UNALIGNED_ACCESS) && defined (TARGET_LITTLE_ENDIAN)
    auto    p = (const uint64_t *)(&state_ [8]) ;
    return *p ;
#else
    return (  (static_cast<uint64_t> (state_ [8]) <<  0)
            | (static_cast<uint64_t> (state_ [9]) << 32)) ;
#endif
}

void    Salsa20::State::SetSequenceNumber (uint64_t value) {
#if defined (TARGET_ALLOWS_UNALIGNED_ACCESS) && defined (TARGET_LITTLE_ENDIAN)
    auto    p = (uint64_t *)(&state_ [8]) ;
    *p = value ;
#else
    state_ [8] = static_cast<uint32_t> (value >>  0) ;
    state_ [9] = static_cast<uint32_t> (value >> 32) ;
#endif
}

void    Salsa20::State::IncrementSequenceNumber () {
#if defined (TARGET_ALLOWS_UNALIGNED_ACCESS) && defined (TARGET_LITTLE_ENDIAN)
    auto    p = (uint64_t *)(&state_ [8]) ;
    ++(*p) ;
#else
    uint64_t tmp = (  (static_cast<uint64_t> (state_ [8]) <<  0)
                    | (static_cast<uint64_t> (state_ [9]) << 32)) ;
    ++tmp ;
    state_ [8] = static_cast<uint32_t> (tmp >>  0) ;
    state_ [9] = static_cast<uint32_t> (tmp >> 32) ;
#endif
}

Salsa20::State &        Salsa20::State::Assign (const Salsa20::State &src) {
    ::memcpy (state_, src.state_, sizeof (state_)) ;
    return *this ;
}

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

Salsa20::hash_value_t   Salsa20::State::ComputeHashValue () const {
    const int   STATE_SIZE = sizeof (state_) / sizeof (state_ [0]) ;

    const int   NUM_ROUNDS = 10 ;

#ifdef HAVE_SSE3
    __m128i     v0orig = _mm_loadu_si128 ((const __m128i *)&state_ [ 0]) ;
    __m128i     v1orig = _mm_loadu_si128 ((const __m128i *)&state_ [ 4]) ;
    __m128i     v2orig = _mm_loadu_si128 ((const __m128i *)&state_ [ 8]) ;
    __m128i     v3orig = _mm_loadu_si128 ((const __m128i *)&state_ [12]) ;

    __m128i     v0 = v0orig ;
    __m128i     v1 = v1orig ;
    __m128i     v2 = v2orig ;
    __m128i     v3 = v3orig ;

    //  3  2  1  0
    //  7  6  5  4
    // 11 10  9  8
    // 15 14 13 12
    v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (0, 3, 2, 1)) ;
    v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
    v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (2, 1, 0, 3)) ;
    //  3  2  1  0
    //  4  7  6  5
    //  9  8 11 10
    // 14 13 12 15
    TRANSPOSE_(v0, v1, v2, v3) ;
    // 15 10  5  0
    // 12 11  6  1
    // 13  8  7  2
    // 14  9  4  3
    SWAP_(v1, v3) ;
    // 15 10  5  0
    // 14  9  4  3
    // 13  8  7  2
    // 12 11  6  1
    v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (0, 3, 2, 1)) ;
    v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
    v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (2, 1, 0, 3)) ;
    // 15 10  5  0
    //  3 14  9  4
    //  7  2 13  8
    // 11  6  1 12
    v1 = _mm_xor_si128 (v1, vrot (_mm_add_epi32 (v0, v3),  7)) ;
    v2 = _mm_xor_si128 (v2, vrot (_mm_add_epi32 (v1, v0),  9)) ;
    v3 = _mm_xor_si128 (v3, vrot (_mm_add_epi32 (v2, v1), 13)) ;
    v0 = _mm_xor_si128 (v0, vrot (_mm_add_epi32 (v3, v2), 18)) ;

    v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (2, 1, 0, 3)) ;
    v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
    v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (0, 3, 2, 1)) ;
    // 15 10  5  0
    // 14  9  4  3
    // 13  8  7  2
    // 12 11  6  1
    v3 = _mm_xor_si128 (v3, vrot (_mm_add_epi32 (v0, v1),  7)) ;
    v2 = _mm_xor_si128 (v2, vrot (_mm_add_epi32 (v3, v0),  9)) ;
    v1 = _mm_xor_si128 (v1, vrot (_mm_add_epi32 (v2, v3), 13)) ;
    v0 = _mm_xor_si128 (v0, vrot (_mm_add_epi32 (v1, v2), 18)) ;
    for (int i = 1 ; i < NUM_ROUNDS ; ++i) {
        // 15 10  5  0
        // 14  9  4  3
        // 13  8  7  2
        // 12 11  6  1
        v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (0, 3, 2, 1)) ;
        v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
        v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (2, 1, 0, 3)) ;
        // 15 10  5  0
        //  3 14  9  4
        //  7  2 13  8
        // 11  6  1 12
        v1 = _mm_xor_si128 (v1, vrot (_mm_add_epi32 (v0, v3),  7)) ;
        v2 = _mm_xor_si128 (v2, vrot (_mm_add_epi32 (v1, v0),  9)) ;
        v3 = _mm_xor_si128 (v3, vrot (_mm_add_epi32 (v2, v1), 13)) ;
        v0 = _mm_xor_si128 (v0, vrot (_mm_add_epi32 (v3, v2), 18)) ;

        v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (2, 1, 0, 3)) ;
        v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (1, 0, 3, 2)) ;
        v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (0, 3, 2, 1)) ;
        // 15 10  5  0
        // 14  9  4  3
        // 13  8  7  2
        // 12 11  6  1
        v3 = _mm_xor_si128 (v3, vrot (_mm_add_epi32 (v0, v1),  7)) ;
        v2 = _mm_xor_si128 (v2, vrot (_mm_add_epi32 (v3, v0),  9)) ;
        v1 = _mm_xor_si128 (v1, vrot (_mm_add_epi32 (v2, v3), 13)) ;
        v0 = _mm_xor_si128 (v0, vrot (_mm_add_epi32 (v1, v2), 18)) ;
    }
    TRANSPOSE_ (v0, v1, v2, v3) ;
    //  1  2  3  0
    //  6  7  4  5
    // 11  8  9 10
    // 12 13 14 15
    v0 = _mm_shuffle_epi32 (v0, _MM_SHUFFLE (1, 2, 3, 0)) ;
    v1 = _mm_shuffle_epi32 (v1, _MM_SHUFFLE (2, 3, 0, 1)) ;
    v2 = _mm_shuffle_epi32 (v2, _MM_SHUFFLE (3, 0, 1, 2)) ;
    v3 = _mm_shuffle_epi32 (v3, _MM_SHUFFLE (0, 1, 2, 3)) ;
    //  3  2  1  0
    //  7  6  5  4
    // 11 10  9  8
    // 15 14 13 12
    v0 = _mm_add_epi32 (v0, v0orig) ;
    v1 = _mm_add_epi32 (v1, v1orig) ;
    v2 = _mm_add_epi32 (v2, v2orig) ;
    v3 = _mm_add_epi32 (v3, v3orig) ;

    hash_value_t result ;
    {
        _mm_storeu_si128 ((__m128i *)&result [ 0], v0) ;
        _mm_storeu_si128 ((__m128i *)&result [16], v1) ;
        _mm_storeu_si128 ((__m128i *)&result [32], v2) ;
        _mm_storeu_si128 ((__m128i *)&result [48], v3) ;
    }
    return result ;
#else
    uint32_t    x [STATE_SIZE] ;

    for (int i = 0 ; i < STATE_SIZE ; ++i) {
        x [i] = state_ [i] ;
    }
    for (int i = 0 ; i < NUM_ROUNDS ; ++i) {
        x[ 4] ^= rot (x[ 0] + x[12],  7) ;
        x[ 8] ^= rot (x[ 4] + x[ 0],  9) ;
        x[12] ^= rot (x[ 8] + x[ 4], 13) ;
        x[ 0] ^= rot (x[12] + x[ 8], 18) ;

        x[ 9] ^= rot (x[ 5] + x[ 1],  7) ;
        x[13] ^= rot (x[ 9] + x[ 5],  9) ;
        x[ 1] ^= rot (x[13] + x[ 9], 13) ;
        x[ 5] ^= rot (x[ 1] + x[13], 18) ;

        x[14] ^= rot (x[10] + x[ 6],  7) ;
        x[ 2] ^= rot (x[14] + x[10],  9) ;
        x[ 6] ^= rot (x[ 2] + x[14], 13) ;
        x[10] ^= rot (x[ 6] + x[ 2], 18) ;

        x[ 3] ^= rot (x[15] + x[11],  7) ;
        x[ 7] ^= rot (x[ 3] + x[15],  9) ;
        x[11] ^= rot (x[ 7] + x[ 3], 13) ;
        x[15] ^= rot (x[11] + x[ 7], 18) ;
        //
        x[ 1] ^= rot (x[ 0] + x[ 3],  7) ;
        x[ 2] ^= rot (x[ 1] + x[ 0],  9) ;
        x[ 3] ^= rot (x[ 2] + x[ 1], 13) ;
        x[ 0] ^= rot (x[ 3] + x[ 2], 18) ;

        x[ 6] ^= rot (x[ 5] + x[ 4],  7) ;
        x[ 7] ^= rot (x[ 6] + x[ 5],  9) ;
        x[ 4] ^= rot (x[ 7] + x[ 6], 13) ;
        x[ 5] ^= rot (x[ 4] + x[ 7], 18) ;

        x[11] ^= rot (x[10] + x[ 9],  7) ;
        x[ 8] ^= rot (x[11] + x[10],  9) ;
        x[ 9] ^= rot (x[ 8] + x[11], 13) ;
        x[10] ^= rot (x[ 9] + x[ 8], 18) ;

        x[12] ^= rot (x[15] + x[14],  7) ;
        x[13] ^= rot (x[12] + x[15],  9) ;
        x[14] ^= rot (x[13] + x[12], 13) ;
        x[15] ^= rot (x[14] + x[13], 18) ;
    }

    hash_value_t    result ;
    for (int i = 0 ; i < STATE_SIZE ; ++i) {
        uint32_t        v = x [i] + state_ [i] ;

        result [4 * i + 0] = static_cast<unsigned char> (v >>  0) ;
        result [4 * i + 1] = static_cast<unsigned char> (v >>  8) ;
        result [4 * i + 2] = static_cast<unsigned char> (v >> 16) ;
        result [4 * i + 3] = static_cast<unsigned char> (v >> 24) ;
    }
    return result ;
#endif
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

void    Salsa20::Apply (Salsa20::State &state, void *dst, const void *src, size_t length) {

    auto    p = static_cast<const uint8_t *> (src) ;
    auto    q = static_cast<uint8_t *> (dst) ;

    size_t  cnt = length / std::tuple_size<hash_value_t>::value ;
    for (size_t i = 0 ; i < cnt ; ++i) {
        auto const hash = state.ComputeHashValue () ;
        state.IncrementSequenceNumber () ;

        for (size_t i = 0 ; i < hash.size () ; ++i) {
            q [i] = p [i] ^ hash [i] ;
        }
        p += hash.size () ;
        q += hash.size () ;
    }
    size_t remain = length - (cnt * std::tuple_size<hash_value_t>::value) ;
    if (0 < remain) {
        auto const hash = state.ComputeHashValue () ;
        state.IncrementSequenceNumber () ;

        for (size_t i = 0 ; i < remain ; ++i) {
            q [i] = p [i] ^ hash [i] ;
        }
    }
}


/**
 * Converts byte offset into the sequence number.
 *
 * @param offset Byte offset from the beginning
 *
 * @returns Sequence number
 */
static inline uint64_t  OffsetToSequenceNumber (uint64_t offset) {
    return offset / std::tuple_size <Salsa20::hash_value_t>::value ;
}

void    Salsa20::Apply (Salsa20::State &state, void *dst, const void *src, size_t length, uint64_t offset) {
    auto    p = static_cast<const uint8_t *> (src) ;
    auto    q = static_cast<uint8_t *> (dst) ;
    auto    end = p + length ;

    state.SetSequenceNumber (OffsetToSequenceNumber (offset)) ;
    auto hash = state.ComputeHashValue () ;

    size_t      i = static_cast<size_t> (offset % hash.size ()) ;
    while (p < end) {
        *q++ = *p++ ^ hash [i++] ;
        if (hash.size () <= i) {
            state.IncrementSequenceNumber () ;
            hash = state.ComputeHashValue () ;
            i = 0 ;
        }
    }
}

void    Salsa20::Apply (Salsa20::State &state, void *message, size_t length) {

    auto    p = static_cast<uint8_t *> (message) ;

    size_t  cnt = length / std::tuple_size<hash_value_t>::value ;
    for (int i = 0 ; i < cnt ; ++i) {
        auto hash = state.ComputeHashValue () ;
        state.IncrementSequenceNumber () ;

        for (size_t i = 0 ; i < hash.size () ; ++i) {
            p [i] ^= hash [i] ;
        }
        p += hash.size () ;
    }
    size_t remain = length - (cnt * std::tuple_size<hash_value_t>::value) ;
    if (0 < remain) {
        auto const hash = state.ComputeHashValue () ;
        state.IncrementSequenceNumber () ;

        for (size_t i = 0 ; i < remain ; ++i) {
            p [i] ^= hash [i] ;
        }
    }
}

void    Salsa20::Apply (Salsa20::State &state, void *message, size_t length, uint64_t offset) {

    auto    p = static_cast<uint8_t *> (message) ;
    auto    end = p + length ;

    state.SetSequenceNumber (OffsetToSequenceNumber (offset)) ;
    auto hash = state.ComputeHashValue () ;

    size_t      i = static_cast<size_t> (offset % hash.size ()) ;
    while (p < end) {
        *p++ ^= hash [i++] ;
        if (sizeof (hash) <= i) {
            state.IncrementSequenceNumber () ;
            hash = state.ComputeHashValue () ;
            i = 0 ;
        }
    }
}
/*
 * [END OF FILE]
 */
