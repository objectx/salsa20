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
        /**
         * Sets the key.
         *
         * @param key The Key to use
         */
        void    SetKey (const void *key, size_t key_size) ;
        /**
         * Sets the initial vector.
         *
         * @param iv The initial vector
         */
        void    SetInitialVector (uint64_t iv) ;
        /**
         * Retrieves current sequence number.
         */
        uint64_t    GetSequenceNumber () const ;
        /**
         * Sets the sequence number.
         *
         * @param value The sequence number
         */
        void    SetSequenceNumber (uint64_t value) ;
        /**
         * Increments the sequence number by 1.
         */
        void    IncrementSequenceNumber () ;

        State & Assign (const State &src) ;
        State & operator = (const State &src) {
            return Assign (src) ;
        }

        /**
         * Computes the hash value.
         *
         * @param name h Computed hash value.
         */
        void    ComputeHashValue (hash_value_t &h) const ;
    } ;

    /**
     * Performs Salsa20 encryption.
     *
     * @param state The encryption state
     * @param dst The output
     * @param src The input
     * @param length The input length
     *
     * @remarks The Salsa20 cipher is the invertible cipher.
     */
    extern void Apply (Salsa20::State &state, void *dst, const void *src, size_t length) ;

    /**
     * Performs Salsa20 encryption.
     *
     * @param state The encryption state
     * @param dst The output
     * @param src The input
     * @param length The input length
     * @param offset The start offset
     *
     * @remarks The Salsa20 cipher is the invertible cipher.
     */
    extern void Apply (Salsa20::State &state, void *dst, const void *src, size_t length, uint64_t offset) ;

    /**
     * Performs the Salsa20 in-place encryption.
     *
     * @param state The encryption state
     * @param message The message
     * @param length The message length
     *
     * @remarks The Salsa20 cipher is the invertible cipher.
     */
    extern void Apply (Salsa20::State &state, void *message, size_t length) ;

    /**
     * Performs the Salsa20 in-place encryption.
     *
     * @param state The encryption state
     * @param message The message
     * @param length The message length
     * @param offset The start offset
     *
     * @remarks The Salsa20 cipher is the invertible cipher.
     */
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
