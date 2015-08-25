/*
 **********************************************************************
 ** md5.h -- Header file for implementation of MD5                   **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 12/27/90 SRD,AJ,BSK,JT Reference C version              **
 ** Revised (for MD5): RLR 4/27/91                                   **
 **   -- G modified to have y&~z instead of y&z                      **
 **   -- FF, GG, HH modified to add in last register done            **
 **   -- Access pattern: round 2 works mod 5, round 3 works mod 3    **
 **   -- distinct additive constant for each step                    **
 **   -- round 4 added, working mod 7                                **
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

#ifndef md5_h__bf1a5e87_1d10_8345_bd70_ff286b0517b8
#define	md5_h__bf1a5e87_1d10_8345_bd70_ff286b0517b8	1

#if defined (_MSC_VER) && (1200 <= _MSC_VER)
#pragma once
#endif

#include <sys/types.h>
#include <assert.h>
#include <string>
#include <iostream>

/// <summary>Computes MD5 value.</summary>
class MD5Generator
{
public:
  typedef unsigned int	uint32_t ;
  typedef unsigned char	uint8_t ;

  /// <summary>Represents computed MD5 value.</summary>
  class Digest
  {
    friend class MD5Generator ;
  private:
    uint8_t	value_ [16] ;
  private:
    Digest (const uint32_t *buf) ;
    void	init_from_string (const char *s, size_t len) ;
  public:
    Digest (const Digest &src) ;
    Digest (const char *s, size_t len) { init_from_string (s, len) ; }
    Digest (const std::string &src) { init_from_string (src.c_str (), src.size ()) ; }
    Digest &	assign (const Digest &src) ;
    Digest &	operator = (const Digest &src) { return assign (src) ; }

    size_t	size () const { return 16 ; }
    uint8_t	at (size_t idx) const
    {
      assert (idx < 16) ;
      return value_ [idx] ;
    }
    uint8_t	operator [] (size_t idx) const
    {
      assert (idx < 16) ;
      return value_ [idx] ;
    }
    std::string	toString () const ;
    operator std::string () const { return toString () ;}
  public:
    static bool	is_equal (const Digest &a0, const Digest &a1) ;
    static bool	is_not_equal (const Digest &a0, const Digest &a1) ;
    static int	compare (const Digest &a0, const Digest &a1) ;

    friend bool	operator == (const Digest &a0, const Digest &a1)
      { return is_equal (a0, a1) ; }
    friend bool	operator != (const Digest &a0, const Digest &a1)
      { return is_not_equal (a0, a1) ; }
    friend bool operator <  (const Digest &a0, const Digest &a1)
      { return compare (a0, a1) <= 0 ; }
    friend bool operator <= (const Digest &a0, const Digest &a1)
      { return compare (a0, a1) <= 0 ; }
    friend bool operator >  (const Digest &a0, const Digest &a1)
      { return compare (a0, a1) > 0 ; }
    friend bool operator >= (const Digest &a0, const Digest &a1)
      { return compare (a0, a1) >= 0 ; }
    friend std::ostream &	operator << (std::ostream &out, const Digest &digest) ;
  } ;
private:
  uint32_t	i_ [2] ;	// # of bits handled (mod 2^64)
  uint32_t	buf_ [4] ;	// scratch buffer
  uint8_t	in_ [64] ;	// input buffer
  bool		finalized_ ;

public:
  /// <summary>The constructor.</summary>
  MD5Generator () ;

  /// <summary>Resets internal states.</summary>
  void	reset () ;
  /// <summary>Updates digest.</summary>
  /// <param name="input">Start of the byte sequence</param>
  /// <param name="size"># of bytes to process</param>
  void	update (const void *input, size_t size) ;
  /// <summary>Finalizes digest.</summary>
  /// <return>Computed MD5 value</return>
  /// <seealso cref="MD5Generator::Digest"/>
  Digest	finalize () ;
  /// <summary>Retrieves computed digest value.</summary>
  /// <return>Computed MD5 value</return>
  /// <seealso cref="MD5Generator::Digest"/>
  Digest	getDigest () const ;
public:
  /// <summary>Computes MD5 value from supplied byte sequence.</summary>
  /// <param name="data">Top of the byte sequence</param>
  /// <param name="size"># of bytes to process</param>
  /// <return>Computed MD5 value</return>
  /// <seealso cref="MD5Generator::Digest"/>
  static Digest	getDigest (const void *data, size_t size) ;
} ;

#endif	/* md5_h__bf1a5e87_1d10_8345_bd70_ff286b0517b8 */
/*
 * $LastChangedBy: objectx $
 * $LastChangedRevision: 2563 $
 * $HeadURL: http://svn.polyphony.scei.co.jp/developer/objectx/trunk/workspace/VS2005/Native/Salsa20/test_salsa20/md5.h $
 */
