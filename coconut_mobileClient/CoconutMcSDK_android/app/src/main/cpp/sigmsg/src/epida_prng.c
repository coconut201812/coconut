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
 * \brief Pseudo random number generator implementation.
 */

/* system header files */
#include <stdlib.h>
#include <time.h>

/* epdia common header files */
#include "include/epida_define.h"
#include "epid/ipp/ippcp.h"

/* current module header files */
#include "sigmsg/epida_prng.h"

EpidStatus PrngCreate(VOID** prng)
{
	EpidStatus sts = kEpidErr;
	INT32 prng_ctx_size = 0;
	IppsPRNGState* prng_ctx = NULL;
	INT32 seed_ctx_size = 0;
	IppsBigNumState* seed_ctx = NULL;
	time_t seed_value;

	if (NULL == prng)
	{
		return kEpidBadArgErr;
	}

	if (ippStsNoErr != ippsPRNGGetSize(&prng_ctx_size))
	{
		return kEpidErr;
	}

	if (ippStsNoErr != ippsBigNumGetSize((sizeof(seed_value) + 3) / 4, &seed_ctx_size))
	{
		return kEpidErr;
	}

	do
	{
		prng_ctx = (IppsPRNGState*)calloc(1, prng_ctx_size);
		if (NULL == prng_ctx)
		{
			sts = kEpidNoMemErr;
			break;
		}

		if (ippStsNoErr != ippsPRNGInit(sizeof(seed_value) * 8, prng_ctx)) 
		{
			sts = kEpidErr;
			break;
		}

		// seed PRNG
		seed_ctx = (IppsBigNumState*)calloc(1, seed_ctx_size);
		if (NULL == seed_ctx)
		{
			sts = kEpidNoMemErr;
			break;
		}
		if (ippStsNoErr != ippsBigNumInit((sizeof(seed_value) + 3) / 4, seed_ctx)) 
		{
			sts = kEpidErr;
			break;
		}
		time(&seed_value);
		if (ippStsNoErr != ippsSetOctString_BN((void*)&seed_value, sizeof(seed_value), seed_ctx)) 
		{
			sts = kEpidErr;
			break;
		}
		if (ippStsNoErr != ippsPRNGSetSeed(seed_ctx, prng_ctx)) 
		{
			sts = kEpidErr;
			break;
		}

		*prng = prng_ctx;
		prng_ctx = NULL;
		sts = kEpidNoErr;
	} while (0);

    EPIDA_SAFE_FREE(seed_ctx);
    EPIDA_SAFE_FREE(prng_ctx);

	return sts;
}

VOID PrngDelete(VOID** prng)
{
	if ( (NULL != prng) && (NULL != *prng) )
	{
		free(*prng);
		*prng = NULL;
	}

	return;
}

// simple wrapper to hide IPP implementation.
INT32 __STDCALL PrngGen(UINT32* rand_data, INT32 num_bits, VOID* user_data)
{
	return ippsPRNGen(rand_data, num_bits, (IppsPRNGState*)user_data);
}
