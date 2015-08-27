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

static inline uint32_t ToInt32 (const void *start) {
    auto p = static_cast<const uint8_t *> (start) ;

    return (  (static_cast<uint32_t> (p [0]) <<  0)
            | (static_cast<uint32_t> (p [1]) <<  8)
            | (static_cast<uint32_t> (p [2]) << 16)
            | (static_cast<uint32_t> (p [3]) << 24)) ;
}

static inline uint32_t  rot (uint32_t x, size_t n) {
#if defined (_MSC_VER) && (1200 <= _MSC_VER)
    return _rotl (x, n) ;
#else
    return(x << n) | (x >> (32 - n)) ;
#endif
}

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
    return (  (static_cast<uint64_t> (state_ [8]) <<  0)
            | (static_cast<uint64_t> (state_ [9]) << 32)) ;
}

void    Salsa20::State::SetSequenceNumber (uint64_t value) {
    state_ [8] = static_cast<uint32_t> (value >>  0) ;
    state_ [9] = static_cast<uint32_t> (value >> 32) ;
}

void    Salsa20::State::IncrementSequenceNumber () {
    uint32_t    val = (state_ [8] += 1) ;
    if (val == 0) {
        state_ [9] += 1 ;
    }
}

Salsa20::State &        Salsa20::State::Assign (const Salsa20::State &src) {
    ::memcpy (state_, src.state_, sizeof (state_)) ;
    return *this ;
}

Salsa20::hash_value_t   Salsa20::State::ComputeHashValue () const {
    const int   STATE_SIZE = sizeof (state_) / sizeof (state_ [0]) ;

    const int   NUM_ROUNDS = 10 ;

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
