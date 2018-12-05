/*############################################################################
  # Copyright 2018 BITMAINTECH PTE LTD.
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
############################################################################*/
/*!
 * \file
 * \Random data supplier interface
 */

#ifndef _EPIDA_ENTROPY_H_
#define _EPIDA_ENTROPY_H_

#if defined(_WIN32) || defined(_WIN64)
#define __STDCALL __stdcall
#else
#define __STDCALL
#endif

/// Allocate and initialize context for bit supplier
/*!
  \param[in] filename
  file name to read random bits from. If null, a pseudo-random number
  generator will be used.

  \returns Returns a pointer to a valid context. On error, returns a
  null pointer.
 */
VOID* NewBitSupplier(CHAR const* filename);

// Free bit supplier context
VOID DeleteBitSupplier(VOID** ctx);

/// Provides random bits.
/*!

  \param[out] rand_data
  destination buffer for random data. The buffer will receive
  `num_bits` of random data.

  \param[in] num_bits
  specifies the size of the random data, in bits, to be generated.

  \param[in] ctx
  The bit supplier context, allocated with NewBitSupplier.

  \returns zero on success and non-zero value on error.
*/
INT32 __STDCALL SupplyBits(UINT32* rand_data, INT32 num_bits, VOID* ctx);

/// Checks if SupplyBits had enough bytes of entropy
/*!

  \note Should be used after a call to SupplyBits.

  \see SupplyBits

  \param[in] bs_ctx
  The bit supplier context, allocated with NewBitSupplier.

  \returns zero if entropy file contains enough bytes for bit supplier and
  non-zero value if there are not enough bytes.
*/
INT32 NotEnoughBytesOfEntropyProvided(VOID* bs_ctx);

#endif  // TOOLS_JOINREQ_SRC_ENTROPY_H_
