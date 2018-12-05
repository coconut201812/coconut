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
 * \Random data supplier implementation
 */

/* system header files */
#include <limits.h>  // for CHAR_BIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* epida common header files */
#include "include/epida_define.h"
#include "sigmsg/epida_prng.h"

/* current module header files */
#include "sigmsg/epida_entropy.h"

typedef struct BitSupplierCtx 
{
	FILE* randfile;
	VOID* prng;

	// SupplyBits error flag
	INT32 not_enough_entropy_bytes;
} BitSupplierCtx;

VOID* NewBitSupplier(CHAR const* filename)
{
	BitSupplierCtx* ctx = NULL;
	EpidStatus sts = kEpidNoErr;
	
	do
	{
		ctx = (BitSupplierCtx*)malloc(sizeof(BitSupplierCtx));
		if (NULL == ctx)
		{
			break;
		}

		if (NULL != filename)
		{
			ctx->prng = NULL;
		
			// use entropy from file
			ctx->randfile = fopen(filename, "rb");
			if (NULL == ctx->randfile)
			{
				sts = kEpidErr;
				break;
			}
		} 
		else
		{
			// use PRNG
			ctx->randfile = NULL;
			sts = PrngCreate(&ctx->prng);
		}

		ctx->not_enough_entropy_bytes = 0;
	} while (0);

	if (kEpidNoErr != sts)
	{
		DeleteBitSupplier((VOID**)&ctx);
	}

	return ctx;
}

VOID DeleteBitSupplier(VOID** bs_ctx) 
{
	BitSupplierCtx* ctx = (BitSupplierCtx*)*bs_ctx;
	
	if (NULL != ctx)
	{
		if (NULL != ctx->randfile)
		{
			fclose(ctx->randfile);
		}
		if (NULL != ctx->prng)
		{
			PrngDelete(&ctx->prng);
		}

		ctx->not_enough_entropy_bytes = 0;
        EPIDA_SAFE_FREE(*bs_ctx);
	}

	return;
}

INT32 __STDCALL SupplyBits(UINT32* rand_data, INT32 num_bits, VOID* user_data) 
{
	BitSupplierCtx* ctx = (BitSupplierCtx*)user_data;
	
	if ( (NULL != ctx) && (NULL != ctx->randfile) )
	{
		size_t bytes_read = 0;
		UINT32 num_bytes = (num_bits + CHAR_BIT - 1) / CHAR_BIT;
		bytes_read = fread(rand_data, 1, num_bytes, ctx->randfile);
		if (bytes_read == num_bytes)
		{
			return EPIDA_OK;
		} 
		else
		{
			ctx->not_enough_entropy_bytes = 1;
			return EPIDA_ERR;
		}
	} 
	else if ( (NULL != ctx) && (NULL != ctx->prng) ) 
	{
		return PrngGen(rand_data, num_bits, ctx->prng);
	}
	else
	{
		//do nothing
	}

	return EPIDA_ERR;
}

INT32 NotEnoughBytesOfEntropyProvided(VOID* bs_ctx)
{
	BitSupplierCtx* ctx = (BitSupplierCtx*)bs_ctx;
	
	if (ctx->not_enough_entropy_bytes) 
	{
		return 1;
	}

	return 0;
}
