/*
 * main.cxx:
 *
 * AUTHOR(S): objectx
 *
 * $Id: main.cxx 2563 2007-11-22 12:26:29Z objectx $
 */

#include "common.h"
#include "md5.h"
#include "salsa20.h"

static unsigned int     to_uint (int a, int b, int c, int d)
{
    return ((static_cast<unsigned int> (a & 0xFF) <<  0) |
            (static_cast<unsigned int> (b & 0xFF) <<  8) |
            (static_cast<unsigned int> (c & 0xFF) << 16) |
            (static_cast<unsigned int> (d & 0xFF) << 24)) ;
}

static uint64_t to_uint (int a, int b, int c, int d, int e, int f, int g, int h)
{
    return ((static_cast<uint64_t> (a & 0xFF) <<  0) |
            (static_cast<uint64_t> (b & 0xFF) <<  8) |
            (static_cast<uint64_t> (c & 0xFF) << 16) |
            (static_cast<uint64_t> (d & 0xFF) << 24) |
            (static_cast<uint64_t> (e & 0xFF) << 32) |
            (static_cast<uint64_t> (f & 0xFF) << 40) |
            (static_cast<uint64_t> (g & 0xFF) << 48) |
            (static_cast<uint64_t> (h & 0xFF) << 56)) ;
}


class put_int {
private:
    int value_ ;
    int width_ ;
public:
    put_int (int value, int width = 0) :
        value_ (value), width_ (width) {
        /* NO-OP */
    }
    friend std::ostream & operator << (std::ostream &out, const put_int &arg) {
        std::ios::fmtflags      flag = out.setf (std::ios::dec, std::ios::basefield) ;
        out.width (arg.width_) ;
        out << arg.value_ ;
        out.setf (flag, std::ios::basefield) ;
        return out ;
    }
} ;


class put_hex {
private:
    int value_ ;
    int width_ ;
public:
    put_hex (int value, int width = 0) :
        value_ (value), width_ (width) {
        /* NO-OP */
    }
    friend std::ostream & operator << (std::ostream &out, const put_hex &arg) {
        std::ios::fmtflags      flag = out.setf (std::ios::hex, std::ios::basefield) ;
        char    fill = out.fill ('0') ;
        out.width (arg.width_) ;
        out << arg.value_ ;
        out.fill (fill) ;
        out.setf (flag, std::ios::basefield) ;
        return out ;
    }
};


static void     simple_test ()
{
    static const unsigned char     key [] = {
        1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,
        201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216
    } ;

    uint64_t    IV = to_uint (101, 102, 103, 104, 105, 106, 107, 108) ;
    {
        Salsa20::State  state (key, sizeof (key), IV) ;
        state.SetSequenceNumber (to_uint (109, 110, 111, 112, 113, 114, 115, 116)) ;
        Salsa20::hash_value_t   result ;

        state.ComputeHashValue (result) ;
        int col = 0 ;
        for (int i = 0 ; i < sizeof (result) ; ++i) {
            std::cout << put_int (static_cast<unsigned int> (result [i]), 3) << ' ' ;
            if (16 <= ++col) {
                col = 0 ;
                std::cout << std::endl ;
            }
        }
    }
    std::cout << std::endl ;
    {
        Salsa20::State  state (key, 16, IV) ;
        state.SetSequenceNumber (to_uint (109, 110, 111, 112, 113, 114, 115, 116)) ;

        Salsa20::hash_value_t   result ;

        state.ComputeHashValue (result) ;
        int col = 0 ;
        for (int i = 0 ; i < sizeof (result) ; ++i) {
            std::cout << put_int (static_cast<unsigned int> (result [i]), 3) << ' ' ;
            if (16 <= ++col) {
                col = 0 ;
                std::cout << std::endl ;
            }
        }
    }
}

static void     bigtest ()
{
    unsigned char m [4096] ;
    unsigned char c [4096] ;
    unsigned char d [4096] ;
    unsigned char k [32] ;
    unsigned char v [8] ;

    memset (m, 0, sizeof (m)) ;
    memset (c, 0, sizeof (c)) ;
    memset (d, 0, sizeof (d)) ;
    memset (k, 0, sizeof (k)) ;
    memset (v, 0, sizeof (v)) ;

    Salsa20::State      state ;

    for (int loop = 0 ; loop < 10 ; ++loop) {
        MD5Generator    md5 ;

        for (int bytes = 0 ; bytes <= sizeof (m) ; ++bytes) {

            if (loop & 1) {
                state.SetKey (k, 32) ;
            }
            else {
                state.SetKey (k, 16) ;
            }
            state.SetInitialVector (to_uint (v [0], v [1],  v [2],  v[3], v [4], v [5], v [6], v [7])) ;
            Salsa20::Encrypt (state, c, m, bytes) ;
            md5.update (c, bytes) ;
            state.SetInitialVector (to_uint (v [0], v [1],  v [2],  v[3], v [4], v [5], v [6], v [7])) ;
            Salsa20::Decrypt (state, d, c, bytes) ;
            for (int i = 0 ; i < bytes ; ++i) {
                if (d [i] != m [i]) {
                    std::cout << "Mismatch at position " << put_int (i, 4) << "/" << put_int (bytes, 4) << std::endl ;
                }
            }
            switch (bytes % 3) {
            case 0:
                for (int i = 0 ; (i < bytes) && (i < sizeof (k)) ; ++i) {
                    k [i] ^= c [i] ;
                }
                break ;
            case 1:
                for (int i = 0 ; (i < bytes) && (i <  sizeof (v)) ; ++i) {
                    v [i] ^= c [i] ;
                }
                break ;
            case 2:
                for (int i = 0 ; i < bytes ; ++i) {
                    m [i] = c [i] ;
                }
                break ;
            }
        }
        MD5Generator::Digest    digest (md5.finalize ()) ;

        for (int i = 0 ; i < 16 ; ++i) {
            std::cout << put_hex (digest [i], 2) ;
        }
        for (int i = 0 ; i < 16 ; ++i) {
            std::cout << put_hex (k [16 + i], 2) ;
        }
        std::cout << std::endl ;
    }

    {
        static const int     MAX_LOOP = 134217728 ;
        //static const int        MAX_LOOP = 100000 ;

        MD5Generator    md5 ;
        for (int loop = 0 ; loop < MAX_LOOP ; ++loop) {
            if ((loop % 100000) == 0) {
                std::cerr << '.' << std::flush ;
            }
            Salsa20::Encrypt (state, c, sizeof (c)) ;
            md5.update (c, sizeof (c)) ;
        }
        MD5Generator::Digest    digest (md5.finalize ()) ;
        std::cerr << std::endl ;
        for (int i = 0 ; i < 16 ; ++i) {
            std::cout << put_hex (digest [i], 2) ;
        }
        std::cout << std::endl ;
    }
}

static void     partial_test ()
{
    unsigned char       expected [4096] ;
    unsigned char       actual [4096] ;

    ::memset (expected, 0, sizeof (expected)) ;
    ::memset (actual  , 0, sizeof (actual)) ;
    std::string key_string ("No one could maintain the public order.") ;
    Salsa20::State      state_0 (key_string.c_str (), key_string.size (), 0x87654321) ;
    Salsa20::State      state_1 (state_0) ;
    Salsa20::Apply (state_0, expected, sizeof (expected)) ;

    for (int i = 0 ; i < sizeof (actual) ; i += 7) {
        Salsa20::Apply (state_1, &actual [i], std::min (7, static_cast<int> (sizeof (actual) - i)), i) ;
    }
    std::cout << "Partial test: " ;
    if (::memcmp (expected, actual, sizeof (expected)) != 0) {
        std::cout << "Failed." << std::endl ;
    }
    else {
        std::cout << "Success." << std::endl ;
    }
}

int     main (int argc, char **argv)
{
    partial_test () ;
    simple_test () ;
    bigtest () ;
    return 0 ;
}
/*
 * $LastChangedBy: objectx $
 * $LastChangedRevision: 2563 $
 * $HeadURL: http://svn.polyphony.scei.co.jp/developer/objectx/trunk/workspace/VS2005/Native/Salsa20/test_salsa20/main.cxx $
 */
