/*
 * salsa20.h: The salsa20 cipher
 *
 * AUTHOR(S): objectx
 *
 */
#pragma once
#ifndef salsa20_h__ca34c9a4_6453_9c44_b0eb_08248de3b882
#define salsa20_h__ca34c9a4_6453_9c44_b0eb_08248de3b882 1

#include <cstddef>
#include <cstdint>

namespace Salsa20 {

    typedef unsigned char       hash_value_t [64] ;

    /// <summary>Holds the state for Salsa20.</summary>
    class State {
    private:
        static const uint32_t   obfuscateMask_ ;
        static const uint32_t   sigma_ [4] ;
        static const uint32_t   tau_ [4] ;
    private:
        uint32_t        state_ [16] ;
    public:
        State () ;
        State (const State &src) {
            Assign (src) ;
        }
        State (const void *key, size_t key_size) {
            SetKey (key, key_size) ;
        }
        State (const void *key, size_t key_size, uint64_t iv) {
            SetKey (key, key_size) ;
            SetInitialVector (iv) ;
        }
        /// <summary>Sets the key.</summary>
        /// <param name="key">The key to use</param>
        void    SetKey (const void *key, size_t key_size) ;
        /// <summary>Sets the initial vector.</summary>
        /// <param name="iv">The initial vector</param>
        void    SetInitialVector (uint64_t iv) ;
        /// <summary>Retrieves current sequence number.</summary>
        uint64_t    GetSequenceNumber () const ;
        /// <summary>Sets the sequence number.</summary>
        /// <param name="value">The sequence number</param>
        void    SetSequenceNumber (uint64_t value) ;
        /// <summary>Increments the sequence number by 1.</summary>
        void    IncrementSequenceNumber () ;

        State & Assign (const State &src) ;
        State & operator = (const State &src) {
            return Assign (src) ;
        }

        /// <summary>Computes the hash value</summary>
        /// <param name="h">Computed hash value</param>
        void    ComputeHashValue (hash_value_t &h) const ;
    } ;

    /// <summary>Performs the Salsa20 encryption.</summary>
    /// <param name="state">The encryption state</param>
    /// <param name="dst">The output</param>
    /// <param name="src">The input</param>
    /// <param name="length">The input length</param>
    /// <remarks>The Salsa20 cipher is the invertible cipher.</param>
    extern void Apply (Salsa20::State &state, void *dst, const void *src, size_t length) ;

    /// <summary>Performs the Salsa20 encryption.</summary>
    /// <param name="state">The encryption state</param>
    /// <param name="dst">The output</param>
    /// <param name="src">The input</param>
    /// <param name="length">The input length</param>
    /// <param name="offset">The start offset</param>
    /// <remarks>The Salsa20 cipher is the invertible cipher.</param>
    extern void Apply (Salsa20::State &state, void *dst, const void *src, size_t length, uint64_t offset) ;

    /// <summary>Performs the Salsa20 in-place encryption.</summary>
    /// <param name="state">The encryption state</param>
    /// <param name="message">The message</param>
    /// <param name="length">The message length</param>
    /// <remarks>The Salsa20 cipher is the invertible cipher.</param>
    extern void Apply (Salsa20::State &state, void *message, size_t length) ;

    /// <summary>Performs the Salsa20 in-place encryption.</summary>
    /// <param name="state">The encryption state</param>
    /// <param name="message">The message</param>
    /// <param name="length">The message length</param>
    /// <param name="offset">The start offset</param>
    /// <remarks>The Salsa20 cipher is the invertible cipher.</param>
    extern void Apply (Salsa20::State &state, void *message, size_t length, uint64_t offset) ;

    inline void Encrypt (Salsa20::State &state, void *dst, const void *src, size_t length) {
        Apply (state, dst, src, length) ;
    }
    inline void Encrypt (Salsa20::State &state, void *message, size_t length) {
        Apply (state, message, length) ;
    }

    inline void Encrypt (Salsa20::State &state, void *dst, const void *src, size_t length, uint64_t offset) {
        Apply (state, dst, src, length, offset) ;
    }

    inline void Encrypt (Salsa20::State &state, void *message, size_t length, uint64_t offset) {
        Apply (state, message, length, offset) ;
    }

    inline void Decrypt (Salsa20::State &state, void *dst, const void *src, size_t length) {
        Apply (state, dst, src, length) ;
    }
    inline void Decrypt (Salsa20::State &state, void *message, size_t length) {
        Apply (state, message, length) ;
    }

    inline void Decrypt (Salsa20::State &state, void *dst, const void *src, size_t length, uint64_t offset) {
        Apply (state, dst, src, length, offset) ;
    }

    inline void Decrypt (Salsa20::State &state, void *message, size_t length, uint64_t offset) {
        Apply (state, message, length, offset) ;
    }
} /* end of [namespace Salsa20] */

#endif  /* salsa20_h__ca34c9a4_6453_9c44_b0eb_08248de3b882 */
/*
 * [END OF FILE]
 */
