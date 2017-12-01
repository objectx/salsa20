/*
 * main.cxx:
 *
 * Copyright (c) 2015-2017 Masashi Fujita
 *
 */

#include "common.h"
#include "md5.h"
#include "salsa20.h"
#include <array>

#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include <fmt/format.h>
#include <fmt/ostream.h>

namespace {
    bool    operator== ( const Salsa20::hash_value_t &a
                       , const Salsa20::hash_value_t &b) {
        for (int_fast32_t i = 0 ; i < a.size () ; ++i) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    uint32_t    to_uint (int a, int b, int c, int d) {
        return ( (static_cast<unsigned int> (a & 0xFFu) <<  0)
               | (static_cast<unsigned int> (b & 0xFFu) <<  8)
               | (static_cast<unsigned int> (c & 0xFFu) << 16)
               | (static_cast<unsigned int> (d & 0xFFu) << 24));
    }

    uint64_t    to_uint (int a, int b, int c, int d, int e, int f, int g, int h) {
        return ( (static_cast<uint64_t> (a & 0xFFu) <<  0)
               | (static_cast<uint64_t> (b & 0xFFu) <<  8)
               | (static_cast<uint64_t> (c & 0xFFu) << 16)
               | (static_cast<uint64_t> (d & 0xFFu) << 24)
               | (static_cast<uint64_t> (e & 0xFFu) << 32)
               | (static_cast<uint64_t> (f & 0xFFu) << 40)
               | (static_cast<uint64_t> (g & 0xFFu) << 48)
               | (static_cast<uint64_t> (h & 0xFFu) << 56));
    }

    std::ostream &  operator<< (std::ostream &out, const Salsa20::hash_value_t &value) {
        for (size_t i = 0 ; i < value.size () ; ++i) {
            fmt::print (out, " {0:3d}", value[i]);
        }
        return out;
    }
}

TEST_CASE ("Simple salsa20 test", "[simple]") {
    auto const  key = std::array<uint8_t, 32> {
          1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,
        201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216
    } ;
    auto const  IV = to_uint (101, 102, 103, 104, 105, 106, 107, 108) ;
    SECTION ("Long key") {
        const Salsa20::hash_value_t expected {  69,  37,  68,  39,  41,  15, 107, 193, 255, 139, 122,   6, 170, 233, 217,  98
                                             ,  89, 144, 182, 106,  21,  51, 200,  65, 239,  49, 222,  34, 215, 114,  40, 126
                                             , 104, 197,   7, 225, 197, 153,  31,   2, 102,  78,  76, 176,  84, 245, 246, 184
                                             , 177, 160, 133, 130,   6,  72, 149, 119, 192, 195, 132, 236, 234, 103, 246,  74 } ;
        Salsa20::State  state (&key [0], key.size (), IV) ;
        state.SetSequenceNumber (to_uint (109, 110, 111, 112, 113, 114, 115, 116)) ;
        auto const result = state.ComputeHashValue () ;

        REQUIRE (result == expected) ;
    }
    SECTION ("Truncated key") {
        const Salsa20::hash_value_t expected {  39, 173,  46, 248,  30, 200,  82,  17,  48, 67, 254, 239,  37,  18,  13, 247
                                             , 241, 200,  61, 144,  10,  55,  50, 185,   6, 47, 246, 253, 143,  86, 187, 225
                                             , 134,  85, 110, 246, 161, 163,  43, 235, 231, 94, 171,  51, 145, 214, 112,  29
                                             ,  14, 232,   5,  16, 151, 140, 183, 141, 171,  9, 122, 181, 104, 182, 177, 193 } ;

        Salsa20::State  state (&key [0], 16, IV) ;
        state.SetSequenceNumber (to_uint (109, 110, 111, 112, 113, 114, 115, 116)) ;

        auto const result = state.ComputeHashValue () ;

        REQUIRE (result == expected) ;
    }
}

TEST_CASE ("Big salsa20 test", "[bigtest][hide]") {
    auto message = std::array<uint8_t, 4096> {} ;
    auto cipher_text = std::array<uint8_t, 4096> {} ;
    auto deciphered = std::array<uint8_t, 4096> {} ;
    auto key = std::array<uint8_t, 32> {} ;
    auto IV = std::array<uint8_t, 8> {} ;

    message.fill (0) ;
    cipher_text.fill (0) ;
    deciphered.fill (0) ;
    key.fill (0) ;
    IV.fill (0) ;

    Salsa20::State  state ;

    SECTION ("Construct state") {
        auto const testvector = std::array<std::string, 10>
                { std::string { "e2d22467015c0ffb0adc5fac0ee88ccf8d467a7f07ab53d4efeac8da47fd833e" }
                , std::string { "42ace6ef6e8dbfa909114e7b3ba45ba8fb8a1ee1215a5cf7099c3d7d54ea7dd2" }
                , std::string { "1db38ebb933ef1969b1f28d9f897fce505d7dc51f5480a37692c3af33f5af678" }
                , std::string { "96858517a69b888de857855809e12779b1d664b624a833b5557c6f2c5d86c890" }
                , std::string { "b6dde6c97a15a8d97440e39d191288ff51adbc7e97b8d2ccb128a47df0800202" }
                , std::string { "7b057f22ee78a6496310686ddc7417824eedd94d4be1ebe8d1166cc23fe6123a" }
                , std::string { "4eea51772404b0fb77ce3f37f19a19f2e758f3aa672f4850c936a7b8cd4a5230" }
                , std::string { "13cdd99b631fdc5c6355985eed37507b015d07236b41a3ab1d04d1721e243b48" }
                , std::string { "247b71ca788aea9c0aae22cc7988d42f5efe3f24782b9481a61620719c7a3c9b" }
                , std::string { "1c47c12a40457949d723b86e97a9f2989344ea7bbad6be8a24b0d3486aa954e1" } } ;

        for (int loop = 0 ; loop < 10 ; ++loop) {
            MD5Generator    md5 ;

            for (int bytes = 0 ; bytes <= message.size () ; ++bytes) {
                state.SetKey (key.data (), ((loop & 1) != 0) ? 32 : 16) ;

                state.SetInitialVector (to_uint (IV[0], IV[1],  IV[2],  IV[3], IV[4], IV[5], IV[6], IV[7])) ;
                Salsa20::Encrypt (state, cipher_text.data (), message.data (), bytes) ;
                md5.update (cipher_text.data (), bytes) ;
                state.SetInitialVector (to_uint (IV[0], IV[1],  IV[2],  IV[3], IV[4], IV[5], IV[6], IV[7])) ;
                Salsa20::Decrypt (state, deciphered.data (), cipher_text.data (), bytes) ;

                for (int i = 0 ; i < bytes ; ++i) {
                    if (deciphered[i] != message[i]) {
                        fmt::print (std::cerr, "Mismatched at position {0:4d}/{1:4d}\n", i, bytes) ;
                    }
                }
                switch (bytes % 3) {
                case 0:
                    for (int i = 0 ; i < std::min<int> (bytes, key.size ()) ; ++i) {
                        key[i] ^= cipher_text[i] ;
                    }
                    break ;
                case 1:
                    for (int i = 0 ; i < std::min<int> (bytes, IV.size ()) ; ++i) {
                        IV[i] ^= cipher_text[i] ;
                    }
                    break ;
                case 2:
                    for (int i = 0 ; i < bytes ; ++i) {
                        message[i] = cipher_text[i] ;
                    }
                    break ;
                }
            }
            MD5Generator::Digest    digest { md5.finalize () } ;

            std::stringstream   sout ;
            for (int i = 0 ; i < 16 ; ++i) {
                fmt::print (sout, "{0:02x}", digest [i]) ;
            }
            for (int i = 0 ; i < 16 ; ++i) {
                fmt::print (sout, "{0:02x}", key[16 + i]) ;
            }
            REQUIRE (sout.str () == testvector[loop]) ;
        }
        SECTION ("Long test") {
            static const int     MAX_LOOP = 134217728 ;

            MD5Generator    md5 ;
            for (int loop = 0 ; loop < MAX_LOOP ; ++loop) {
                if ((loop % 100000) == 0) {
                    std::cerr << '.' << std::flush ;
                }
                Salsa20::Encrypt (state, cipher_text.data (), cipher_text.size ()) ;
                md5.update (cipher_text.data (), cipher_text.size ()) ;
            }
            MD5Generator::Digest    digest { md5.finalize () } ;

            std::stringstream   sout ;
            for (int i = 0 ; i < 16 ; ++i) {
                fmt::print (sout, "{0:02x}", digest [i]) ;
            }
            REQUIRE (sout.str () == "dcb0b1043c425ab0eb97a5f30410a685") ;
        }
    }
}

TEST_CASE ("Incremental update", "[incremental update]") {
    auto expected = std::array<uint8_t, 4096> {} ;
    auto actual = std::array<uint8_t, 4096> {} ;

    expected.fill (0) ;
    actual.fill (0) ;
    std::string key_string { "No one could maintain the public order." } ;
    Salsa20::State  state_0 { key_string.c_str (), key_string.size (), 0x87654321u } ;
    Salsa20::State  state_1 { state_0 } ;

    Salsa20::Apply (state_0, expected.data (), expected.size ()) ;

    for (int i = 0 ; i < actual.size () ; i += 7) {
        Salsa20::Apply (state_1, &actual [i], std::min<size_t> (7, actual.size () - i), i) ;
    }
    REQUIRE (::memcmp (expected.data (), actual.data (), actual.size ()) == 0) ;
}

/*
 * [END of FILE]
 */
