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
 * \Message signing implementation to call EPID APIs.
 */

/* system header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* current module header files */
#include "sigmsg/epida_prng.h"
#include "sigmsg/epida_signmsg.h"
#include "util/buffutil.h"


/* get the group public key */
static EpidStatus get_group_pubkey(epida_sig_info_t* sig_info, GroupPubKey* gpubkey)
{
    EpidStatus sts = kEpidNoErr;

    if (sig_info->gpubkey_size == sizeof(GroupPubKey))
    {
        *gpubkey = *((GroupPubKey*)(sig_info->gpubkey));
    }
    else
    {
        sts = EpidParseGroupPubKeyFile(sig_info->gpubkey, sig_info->gpubkey_size,
                                       sig_info->cacert, gpubkey);
    }

    return sts;
}

/* get member private key */
static EpidStatus get_member_privkey(epida_sig_info_t* sig_info, GroupPubKey* public_key,
                                     PrivKey* private_key, MembershipCredential* member_credential)
{
    EpidStatus sts = kEpidNoErr;

    if (sig_info->mprivkey_size == sizeof(PrivKey))
    {
        *private_key = *((PrivKey*)(sig_info->mprivkey));
    }
    else if (sig_info->mprivkey_size == sizeof(CompressedPrivKey))
    {
        sts = EpidDecompressPrivKey(public_key, (CompressedPrivKey*)sig_info->mprivkey, private_key);
    }
    else if (sig_info->mprivkey_size == sizeof(MembershipCredential))
    {
        *member_credential = *((MembershipCredential*)sig_info->mprivkey);
    }
    else
    {
        sts = kEpidErr;
    }

    return sts;
}

EpidStatus SignMsg(epida_sig_info_t* sig_info, EpidSignature** sig, size_t* sig_len)
{
	VOID* prng = NULL;
	SigRl* sig_rl = NULL;
	MemberCtx* member = NULL;
	EpidStatus sts = kEpidErr;

	do
	{
		/* setup local variables for creating member context */
		GroupPubKey pub_key = {0};
		PrivKey priv_key = {0};
		MembershipCredential member_credential = {0};
		size_t sig_rl_size = 0;
		MemberParams params = {0};
		size_t member_size = 0;

		/* check input parameters */
		if (!sig)
		{
			sts = kEpidBadArgErr;
			break;
		}

		/* step-1: extract group public key */
        if (kEpidNoErr != get_group_pubkey(sig_info, &pub_key))
        {
            break;
        }

		/* step-2: handle compressed private key or membership credential */
		if (kEpidNoErr != get_member_privkey(sig_info, &pub_key, &priv_key, &member_credential))
        {
            break;
        }

		/* step-3: create a pseudo-random generator */
		sts = PrngCreate(&prng);
		if (kEpidNoErr != sts)
		{
			break;
		}

		// Indicate that f should be selected by the member.
		// Depending on the implmentation, This might mean
		// selecting a new random value, or it might mean
		// using a value previously stored in a secure location.
		params.f = NULL;
#ifndef TPM_TSS
		// If the implmentation does not have a known secure
		// random number generator one must be supplied.
		params.rnd_func = &PrngGen;
		params.rnd_param = prng;
#endif
#ifdef TINY
		params.max_sigrl_entries = 5;
		params.max_allowed_basenames = 5;
		params.max_precomp_sig = 1;
#endif
	
		// step-4: create member(including the context of a member, for example group public key, member private key, hash-agorithm, etc..)
		sts = EpidMemberGetSize(&params, &member_size);
		if (kEpidNoErr != sts)
		{
			break;
		}
		member = (MemberCtx*)calloc(1, member_size);
		if (!member)
		{
			sts = kEpidNoMemErr;
			break;
		}
		sts = EpidMemberInit(&params, member);
		if (kEpidNoErr != sts)
		{
			break;
		}

		/* 4.1 set private key to sign for member */
		if ( (sig_info->mprivkey_size == sizeof(PrivKey)) || (sig_info->mprivkey_size == sizeof(CompressedPrivKey)) )
		{
			sts = EpidProvisionKey(member, &pub_key, &priv_key, sig_info->member_precomp);
			if (kEpidNoErr != sts)
			{
			    break;
			}
		} 
		else if (sig_info->mprivkey_size == sizeof(MembershipCredential))
		{
			sts = EpidProvisionCredential(member, &pub_key, &member_credential, sig_info->member_precomp);
			if (kEpidNoErr != sts) 
			{
			    break;
			}
		}
		else
		{
			/* do nothing */
		}
		
		/* start member */
		sts = EpidMemberStartup(member);
		if (kEpidNoErr != sts) 
		{
			break;
		}

		/* 4.2: register any provided basename as allowed */
		if (0 != sig_info->basename_len)
		{
			sts = EpidRegisterBasename(member, sig_info->basename, sig_info->basename_len);
			if (kEpidNoErr != sts) 
			{
			    break;
			}
		}

		/* 4.3: set sigRl to sign for member */
		if (sig_info->signed_sig_rl)
		{
			/* authenticate and determine space needed for SigRl */
			sts = EpidParseSigRlFile(sig_info->signed_sig_rl, sig_info->signed_sig_rl_size,
                                     sig_info->cacert, NULL, &sig_rl_size);
			if (kEpidNoErr != sts)
			{
			    break;
			}

			sig_rl = calloc(1, sig_rl_size);
			if (!sig_rl)
			{
				sts = kEpidMemAllocErr;
				break;
			}

			/* extract the SigRl from EPID formatted binary, and fill the SigRl */
			sts = EpidParseSigRlFile(sig_info->signed_sig_rl, sig_info->signed_sig_rl_size,
                                     sig_info->cacert, sig_rl, &sig_rl_size);
			if (kEpidNoErr != sts)
			{
				break;
			}

			sts = EpidMemberSetSigRl(member, sig_rl, sig_rl_size);
			if (kEpidNoErr != sts) 
			{
				break;
			}
		}

		/* step-5: sign message */ 
		/* 5.1: compute the signature size, Note: Signature size must be computed after sig_rl is loaded */
		*sig_len = EpidGetSigSize(sig_rl);
		*sig = calloc(1, *sig_len);
		if (NULL == *sig)
		{
			sts = kEpidMemAllocErr;
			break;
		}

		/* 5.2 sign message by the configuration of member(member context) */
		sts = EpidSign(member, sig_info->msg, sig_info->msg_len, sig_info->basename,
                       sig_info->basename_len, *sig, *sig_len);
		if (kEpidNoErr != sts)
		{
			break;
		}
		sts = kEpidNoErr;
	} while (0);

	/* step-6: cleanup temporary resources */  
	PrngDelete(&prng);
	EpidMemberDeinit(member);

    EPIDA_SAFE_FREE(member);
    EPIDA_SAFE_FREE(sig_rl);

	return sts;
}
