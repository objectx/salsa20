/* --- DO NOT EDIT!  THIS FILE WAS CREATED AUTOMATICALLY --- */
#include "salsa20.h"

namespace Salsa20 {

const uint32_t  State::obfuscateMask_ = 0xABADCAFE ;

const uint32_t  State::sigma_ [] =
{
  0xCADDB29B, 0x988DAE90, 0xD2CFE7CC, 0xC08DAF8A,
} ;

const uint32_t  State::tau_ [] =
{
  0xCADDB29B, 0x9A8DAE90, 0xD2CFE7C8, 0xC08DAF8A,
} ;

}       /* End of namespace [Salsa20] */
/* $Revision$ */
