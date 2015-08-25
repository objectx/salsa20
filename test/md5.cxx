/*
 **********************************************************************
 ** md5.c                                                            **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                  **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

/* -- include the following line if the md5.h header file is separate -- */
#include <string.h>
#include <stdexcept>
#include <string>
#include "md5.h"

/* forward declaration */
//static void Transform (UINT4 *buf, UINT4 *in) ;

static const unsigned char	PADDING [64] =
{
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} ;

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z)	(((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z)	(((x) & (z)) | ((y) & (~z)))
#define H(x, y, z)	((x) ^ (y) ^ (z))
#define I(x, y, z)	((y) ^ ((x) | (~(z))))

#if defined (_MSC_VER) && (1200 <= _MSC_VER)
  #define STDCALL	__stdcall
  /* ROTATE_LEFT rotates x left n bits */
  #define ROTATE_LEFT(x, n) (_rotl ((x), (n)))	/* Using intrinsics... */
  /* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
  #define FF(a, b, c, d, x, s, ac) \
    { (a) = (b) + ROTATE_LEFT ((a) + (x) + (static_cast<MD5Generator::uint32_t>(ac)) + F ((b), (c), (d)), (s)) ; }
  #define GG(a, b, c, d, x, s, ac) \
    { (a) = (b) + ROTATE_LEFT ((a) + (x) + (static_cast<MD5Generator::uint32_t>(ac)) + G ((b), (c), (d)), (s)) ; }
  #define HH(a, b, c, d, x, s, ac) \
    { (a) = (b) + ROTATE_LEFT ((a) + (x) + (static_cast<MD5Generator::uint32_t>(ac)) + H ((b), (c), (d)), (s)) ; }
  #define II(a, b, c, d, x, s, ac) \
    { (a) = (b) + ROTATE_LEFT ((a) + (x) + (static_cast<MD5Generator::uint32_t>(ac)) + I ((b), (c), (d)), (s)) ; }
#else
  #define STDCALL

  /* ROTATE_LEFT rotates x left n bits */
  #define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
  /* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
  /* Rotation is separate from addition to prevent recomputation */
  #define FF(a, b, c, d, x, s, ac)	\
    { (a) += F ((b), (c), (d)) + (x) + (static_cast<MD5Generator::uint32_t> (ac)) ;	\
      (a) = ROTATE_LEFT ((a), (s)) ;	\
      (a) += (b) ; }
  #define GG(a, b, c, d, x, s, ac)	\
    { (a) += G ((b), (c), (d)) + (x) + (static_cast<MD5Generator::uint32_t> (ac)) ;	\
      (a) = ROTATE_LEFT ((a), (s)) ;	\
      (a) += (b) ; }
  #define HH(a, b, c, d, x, s, ac)	\
    { (a) += H ((b), (c), (d)) + (x) + (static_cast<MD5Generator::uint32_t> (ac)) ;	\
      (a) = ROTATE_LEFT ((a), (s)) ;	\
      (a) += (b) ; }
  #define II(a, b, c, d, x, s, ac)	\
    { (a) += I ((b), (c), (d)) + (x) + (static_cast<MD5Generator::uint32_t> (ac)) ;	\
      (a) = ROTATE_LEFT ((a), (s)) ;	\
      (a) += (b) ; }
#endif

/* ------------------------------------------------------------------------ */

/* Basic MD5 step. Transform buf based on in. */
static void	STDCALL transform (MD5Generator::uint32_t *buf, const MD5Generator::uint32_t *in)
{
  MD5Generator::uint32_t	a = buf[0], b = buf[1], c = buf[2], d = buf[3] ;

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
  FF ( a, b, c, d, in [ 0], S11, 3614090360); /*  1 */
  FF ( d, a, b, c, in [ 1], S12, 3905402710); /*  2 */
  FF ( c, d, a, b, in [ 2], S13,  606105819); /*  3 */
  FF ( b, c, d, a, in [ 3], S14, 3250441966); /*  4 */
  FF ( a, b, c, d, in [ 4], S11, 4118548399); /*  5 */
  FF ( d, a, b, c, in [ 5], S12, 1200080426); /*  6 */
  FF ( c, d, a, b, in [ 6], S13, 2821735955); /*  7 */
  FF ( b, c, d, a, in [ 7], S14, 4249261313); /*  8 */
  FF ( a, b, c, d, in [ 8], S11, 1770035416); /*  9 */
  FF ( d, a, b, c, in [ 9], S12, 2336552879); /* 10 */
  FF ( c, d, a, b, in [10], S13, 4294925233); /* 11 */
  FF ( b, c, d, a, in [11], S14, 2304563134); /* 12 */
  FF ( a, b, c, d, in [12], S11, 1804603682); /* 13 */
  FF ( d, a, b, c, in [13], S12, 4254626195); /* 14 */
  FF ( c, d, a, b, in [14], S13, 2792965006); /* 15 */
  FF ( b, c, d, a, in [15], S14, 1236535329); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in [ 1], S21, 4129170786); /* 17 */
  GG ( d, a, b, c, in [ 6], S22, 3225465664); /* 18 */
  GG ( c, d, a, b, in [11], S23,  643717713); /* 19 */
  GG ( b, c, d, a, in [ 0], S24, 3921069994); /* 20 */
  GG ( a, b, c, d, in [ 5], S21, 3593408605); /* 21 */
  GG ( d, a, b, c, in [10], S22,   38016083); /* 22 */
  GG ( c, d, a, b, in [15], S23, 3634488961); /* 23 */
  GG ( b, c, d, a, in [ 4], S24, 3889429448); /* 24 */
  GG ( a, b, c, d, in [ 9], S21,  568446438); /* 25 */
  GG ( d, a, b, c, in [14], S22, 3275163606); /* 26 */
  GG ( c, d, a, b, in [ 3], S23, 4107603335); /* 27 */
  GG ( b, c, d, a, in [ 8], S24, 1163531501); /* 28 */
  GG ( a, b, c, d, in [13], S21, 2850285829); /* 29 */
  GG ( d, a, b, c, in [ 2], S22, 4243563512); /* 30 */
  GG ( c, d, a, b, in [ 7], S23, 1735328473); /* 31 */
  GG ( b, c, d, a, in [12], S24, 2368359562); /* 32 */


  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in [ 5], S31, 4294588738); /* 33 */
  HH ( d, a, b, c, in [ 8], S32, 2272392833); /* 34 */
  HH ( c, d, a, b, in [11], S33, 1839030562); /* 35 */
  HH ( b, c, d, a, in [14], S34, 4259657740); /* 36 */
  HH ( a, b, c, d, in [ 1], S31, 2763975236); /* 37 */
  HH ( d, a, b, c, in [ 4], S32, 1272893353); /* 38 */
  HH ( c, d, a, b, in [ 7], S33, 4139469664); /* 39 */
  HH ( b, c, d, a, in [10], S34, 3200236656); /* 40 */
  HH ( a, b, c, d, in [13], S31,  681279174); /* 41 */
  HH ( d, a, b, c, in [ 0], S32, 3936430074); /* 42 */
  HH ( c, d, a, b, in [ 3], S33, 3572445317); /* 43 */
  HH ( b, c, d, a, in [ 6], S34,   76029189); /* 44 */
  HH ( a, b, c, d, in [ 9], S31, 3654602809); /* 45 */
  HH ( d, a, b, c, in [12], S32, 3873151461); /* 46 */
  HH ( c, d, a, b, in [15], S33,  530742520); /* 47 */
  HH ( b, c, d, a, in [ 2], S34, 3299628645); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in [ 0], S41, 4096336452); /* 49 */
  II ( d, a, b, c, in [ 7], S42, 1126891415); /* 50 */
  II ( c, d, a, b, in [14], S43, 2878612391); /* 51 */
  II ( b, c, d, a, in [ 5], S44, 4237533241); /* 52 */
  II ( a, b, c, d, in [12], S41, 1700485571); /* 53 */
  II ( d, a, b, c, in [ 3], S42, 2399980690); /* 54 */
  II ( c, d, a, b, in [10], S43, 4293915773); /* 55 */
  II ( b, c, d, a, in [ 1], S44, 2240044497); /* 56 */
  II ( a, b, c, d, in [ 8], S41, 1873313359); /* 57 */
  II ( d, a, b, c, in [15], S42, 4264355552); /* 58 */
  II ( c, d, a, b, in [ 6], S43, 2734768916); /* 59 */
  II ( b, c, d, a, in [13], S44, 1309151649); /* 60 */
  II ( a, b, c, d, in [ 4], S41, 4149444226); /* 61 */
  II ( d, a, b, c, in [11], S42, 3174756917); /* 62 */
  II ( c, d, a, b, in [ 2], S43,  718787259); /* 63 */
  II ( b, c, d, a, in [ 9], S44, 3951481745); /* 64 */

  buf [0] += a ;
  buf [1] += b ;
  buf [2] += c ;
  buf [3] += d ;
}

/* ------------------------------------------------------------------------ */

MD5Generator::Digest::Digest (const uint32_t *buf)
{
  for (size_t i = 0, ii = 0; i < 4; i++, ii += 4)
    {
      value_ [ii + 0] = static_cast<uint8_t> (buf [i] >>  0) ;
      value_ [ii + 1] = static_cast<uint8_t> (buf [i] >>  8) ;
      value_ [ii + 2] = static_cast<uint8_t> (buf [i] >> 16) ;
      value_ [ii + 3] = static_cast<uint8_t> (buf [i] >> 24) ;
    }
}

MD5Generator::Digest::Digest (const Digest &src)
{
  memcpy (value_, src.value_, 16) ;
}

static MD5Generator::uint8_t	to_int (char ch)
{
  switch (ch)
    {
    case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
      return static_cast<MD5Generator::uint8_t> (ch - '0') ;
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      return static_cast<MD5Generator::uint8_t> (ch - 'a' + 10) ;
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      return static_cast<MD5Generator::uint8_t> (ch - 'A' + 10) ;
    default:
      throw std::runtime_error ("Bad hexadecimal digit found.") ;
    }
}

void	MD5Generator::Digest::init_from_string (const char *s, size_t len)
{
  if (len != 32)
    throw std::runtime_error ("Badly formed MD5 string.") ;
  for (size_t i = 0 ; i < 16 ; ++i)
    {
      uint8_t	val = (to_int (s [2 * i + 0]) << 4) | (to_int (s [2 * i + 1]) << 0) ;
      value_ [i] = val ;
    }
}


MD5Generator::Digest &	MD5Generator::Digest::assign (const MD5Generator::Digest &src)
{
  memcpy (value_, src.value_, 16) ;
  return *this ;
}


bool    MD5Generator::Digest::is_equal (const Digest &a0, const Digest &a1)
{
  return (a0.value_ [ 0] == a1.value_ [ 0] &&
          a0.value_ [ 1] == a1.value_ [ 1] &&
          a0.value_ [ 2] == a1.value_ [ 2] &&
          a0.value_ [ 3] == a1.value_ [ 3] &&
          a0.value_ [ 4] == a1.value_ [ 4] &&
          a0.value_ [ 5] == a1.value_ [ 5] &&
          a0.value_ [ 6] == a1.value_ [ 6] &&
          a0.value_ [ 7] == a1.value_ [ 7] &&
          a0.value_ [ 8] == a1.value_ [ 8] &&
          a0.value_ [ 9] == a1.value_ [ 9] &&
          a0.value_ [10] == a1.value_ [10] &&
          a0.value_ [11] == a1.value_ [11] &&
          a0.value_ [12] == a1.value_ [12] &&
          a0.value_ [13] == a1.value_ [13] &&
          a0.value_ [14] == a1.value_ [14] &&
          a0.value_ [15] == a1.value_ [15]) ;
}


bool    MD5Generator::Digest::is_not_equal (const Digest &a0, const Digest &a1)
{
  return (a0.value_ [ 0] != a1.value_ [ 0] ||
          a0.value_ [ 1] != a1.value_ [ 1] ||
          a0.value_ [ 2] != a1.value_ [ 2] ||
          a0.value_ [ 3] != a1.value_ [ 3] ||
          a0.value_ [ 4] != a1.value_ [ 4] ||
          a0.value_ [ 5] != a1.value_ [ 5] ||
          a0.value_ [ 6] != a1.value_ [ 6] ||
          a0.value_ [ 7] != a1.value_ [ 7] ||
          a0.value_ [ 8] != a1.value_ [ 8] ||
          a0.value_ [ 9] != a1.value_ [ 9] ||
          a0.value_ [10] != a1.value_ [10] ||
          a0.value_ [11] != a1.value_ [11] ||
          a0.value_ [12] != a1.value_ [12] ||
          a0.value_ [13] != a1.value_ [13] ||
          a0.value_ [14] != a1.value_ [14] ||
          a0.value_ [15] != a1.value_ [15]) ;
}


int	MD5Generator::Digest::compare (const Digest &a0, const Digest &a1)
{
  for (size_t i = 0 ; i < 16 ; ++i)
    {
      int	cmp = (static_cast<unsigned int> (a0.value_ [i]) -
                       static_cast<unsigned int> (a1.value_ [i])) ;
      if (cmp != 0)
        return cmp ;
    }
  return 0 ;
}


std::string	MD5Generator::Digest::toString () const
{
  static const char	tab [] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  } ;
  char	tmp [2 * 16] ;

  for (size_t i = 0 ; i < 16 ; ++i)
    {
      uint8_t	val = value_ [i] ;
      tmp [2 * i + 0] = tab [(val >> 4) & 0x0F] ;
      tmp [2 * i + 1] = tab [(val >> 0) & 0x0F] ;
    }
  return std::string (tmp, 32) ;
}


std::ostream &	operator << (std::ostream &output, const MD5Generator::Digest &digest)
{
  std::ios::fmtflags	flags = output.setf (std::ios::hex, std::ios::basefield) ;
  char	fill = output.fill ('0') ;

  for (size_t i = 0 ; i < 16 ; ++i)
    output << static_cast<unsigned int> (digest.value_ [i]) ;
  output.fill (fill) ;
  output.setf (flags, std::ios::basefield) ;
  return output ;
}

/* ------------------------------------------------------------------------ */

MD5Generator::MD5Generator ()
{
  reset () ;
}

void	MD5Generator::reset ()
{
  i_ [0] = i_ [1] = 0 ;

  /* Load magic initialization constants. */
  buf_ [0] = 0x67452301u ;
  buf_ [1] = 0xEFCDAB89u ;
  buf_ [2] = 0x98BADCFEu ;
  buf_ [3] = 0x10325476u ;
  finalized_ = false ;
}

void MD5Generator::update (const void *input, size_t size)
{
  if (finalized_)
    throw std::runtime_error ("MD5Generator: Already finalized.") ;

  uint32_t	in [16] ;

  int	mdi ;

  /* compute number of bytes mod 64 */
  mdi = (int)((i_ [0] >> 3) & 0x3F) ;

  /* update number of bits */
  if ((i_ [0] + (static_cast<uint32_t> (size) << 3)) < i_ [0])
    ++i_ [1] ;
  i_ [0] += static_cast<uint32_t>(size) << 3 ;
  i_ [1] += static_cast<uint32_t>(size) >> 29;

  const unsigned char *	p = static_cast<const unsigned char *> (input) ;

  while (size--)
    {
      /* add new character to buffer, increment mdi */
      in_ [mdi++] = *p++ ;

      /* transform if necessary */
      if (mdi == 0x40)
        {
          for (size_t i = 0, ii = 0; i < 16; i++, ii += 4)
            {
              in [i] = ((static_cast<uint32_t> (in_ [ii + 3]) << 24) |
                        (static_cast<uint32_t> (in_ [ii + 2]) << 16) |
                        (static_cast<uint32_t> (in_ [ii + 1]) <<  8) |
                        (static_cast<uint32_t> (in_ [ii + 0]) <<  0)) ;
            }
          transform (buf_, in) ;
          mdi = 0;
        }
    }
}

MD5Generator::Digest	MD5Generator::finalize ()
{
  if (! finalized_)
    {
      uint32_t	in [16] ;

      int	mdi ;

      /* save number of bits */
      in [14] = i_ [0] ;
      in [15] = i_ [1] ;

      /* compute number of bytes mod 64 */
      mdi = (int)((i_ [0] >> 3) & 0x3F) ;

      /* pad out to 56 mod 64 */
      size_t	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
      update (PADDING, padLen);

      /* append length in bits and transform */
      for (size_t i = 0, ii = 0; i < 14; i++, ii += 4)
        in [i] = ((static_cast<uint32_t> (in_ [ii + 3]) << 24) |
                  (static_cast<uint32_t> (in_ [ii + 2]) << 16) |
                  (static_cast<uint32_t> (in_ [ii + 1]) <<  8) |
                  (static_cast<uint32_t> (in_ [ii + 0]) <<  0)) ;
      transform (buf_, in) ;
      finalized_ = true ;
    }
  return Digest (buf_) ;
}

MD5Generator::Digest	MD5Generator::getDigest () const
{
  if (! finalized_)
    throw std::runtime_error ("MD5Generator: Not yet finalized.") ;
  return Digest (buf_) ;
}


MD5Generator::Digest	MD5Generator::getDigest (const void *data, size_t size)
{
  MD5Generator	md5 ;

  md5.update (data, size) ;
  return md5.finalize () ;
}

/*
 **********************************************************************
 ** End of md5.c                                                     **
 ******************************* (cut) ********************************
 */

