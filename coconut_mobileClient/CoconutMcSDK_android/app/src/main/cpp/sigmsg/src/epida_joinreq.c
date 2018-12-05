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
 * \Create join request for applying for group certificate implementation:
 */

/* system header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* epida common header files */
#include "include/epida_define.h"
#include "epid/member/api.h"
#include "util/buffutil.h"

/* current module header files */
#include "sigmsg/epida_signmsg.h"
#include "sigmsg/epida_entropy.h"
#include "sigmsg/epida_prng.h"
#include "sigmsg/epida_crypt.h"

#ifdef TPM_TSS
#include "epid/member/tpm_member.h"
#elif defined TINY
#include "epid/member/tiny_member.h"
#else
#include "epid/member/software_member.h"
#endif


typedef struct _tagMemberCtx
{
	GroupPubKey pub_key;              ///< group public key
	HashAlg hash_alg;                 ///< Hash algorithm to use
	MembershipCredential credential;  ///< Membership credential
	FpElemStr f;                  ///< secret f value	
} _MemberCtx;

static EpidStatus MakeJoinRequest(const CHAR* res_directory_path, GroupPubKey const* pub_key,
	      IssuerNonce const* ni, MemberJoinRequest* join_request, BitSupplier rnd_func, VOID* rnd_ctx,
          const CHAR* passphrase, INT32 passphrase_len, UCHAR is_first_random, FpElemStr* value_f)
{
	EpidStatus sts = kEpidNoErr;
	MemberParams params = {0};
	MemberCtx* member = NULL;
	CHAR privatef_file_path[EPIDA_FILE_PATH_MAX] = {0};
    

	if ( (NULL == res_directory_path) || (NULL == pub_key)
		 || (NULL == ni) || (NULL == join_request)
		 || (NULL == passphrase) || (passphrase <= 0)
         || (NULL == value_f) )
	{
		return kEpidBadArgErr;
	}

	snprintf(privatef_file_path, sizeof(privatef_file_path) - 1, "%s%s%s",
		res_directory_path,
		PATH_SLASH,
		PRIVATEF_FILE_NAME);

	do
	{
		size_t member_size = 0;
#if 0
        char privatf_data_1[] = {
            0x15, 0x9D, 0x08, 0x6B, 0x93, 0xBF, 0x95, 0x89, 0x11, 0xB8, 0x31, 0x11, 0xB1, 0x36, 0x76, 0x4D,
            0x0A, 0xBE, 0x5A, 0x42, 0xE7, 0x44, 0xBB, 0x17, 0x6D, 0x36, 0x7B, 0x80, 0x0B, 0x10, 0x1E, 0xC6
        };
#endif
        params.f = (is_first_random) ? NULL : value_f;
#ifdef TPM_TSS
		UNUSED(rnd_func)
		UNUSED(rnd_ctx)
#else
		params.rnd_func = rnd_func;
		params.rnd_param = rnd_ctx;
#endif
	
#ifdef TINY
		params.max_sigrl_entries = 5;
		params.max_allowed_basenames = 5;
		params.max_precomp_sig = 1;
#endif

		// create member
		sts = EpidMemberGetSize(&params, &member_size);
		if (kEpidNoErr != sts)
		{
			break;
		}
		member = (MemberCtx*)calloc(1, member_size);
		if (NULL == member)
		{
			sts = kEpidNoMemErr;
			break;
		}
		sts = EpidMemberInit(&params, member);
		if (kEpidNoErr != sts)
		{
			break;
		}

		sts = EpidCreateJoinRequest(member, pub_key, ni, join_request);
		if (kEpidNoErr != sts) 
		{
			break;
		}
        if (is_first_random)
        {
            *value_f = ((_MemberCtx*)member)->f;
            break;
        }
		
		INT32 cipher_date_len = (INT32)sizeof(FpElemStr);
		UCHAR* cipher_data;
#if 0  /* test data */
		char privatf_data[] = {
            0x15, 0x9D, 0x08, 0x6B, 0x93, 0xBF, 0x95, 0x89, 0x11, 0xB8, 0x31, 0x11, 0xB1, 0x36, 0x76, 0x4D,
            0x0A, 0xBE, 0x5A, 0x42, 0xE7, 0x44, 0xBB, 0x17, 0x6D, 0x36, 0x7B, 0x80, 0x0B, 0x10, 0x1E, 0xC6
		};
        cipher_data = do_encrypt((UCHAR*)passphrase, passphrase_len, (UCHAR*)privatf_data , &cipher_date_len);
#else
		cipher_data = do_encrypt((UCHAR*)passphrase, passphrase_len, (UCHAR*)value_f , &cipher_date_len);
#endif
		if ( (NULL == cipher_data) || (0 == cipher_date_len) )
		{
			sts = kEpidErr;
            break;
		}
		if (0 != WriteLoud((VOID*)cipher_data, cipher_date_len, privatef_file_path))
		{
			sts = kEpidErr;
            break;
		}
        memset(value_f, 0, sizeof(*value_f));
	} while (0);
    
	EpidMemberDeinit(member);
	EPIDA_SAFE_FREE(member);

	return sts;
}

/// Loads a Ca Certificate
INT32 LoadCaCert(CHAR const* filename, EpidCaCertificate* cacert) 
{
	// CA certificate
	if (0 != ReadLoud(filename, cacert, sizeof(*cacert)))
	{
		return EPIDA_ERR;
	}

	// Security note:
	// Application must confirm that IoT Intel(R) EPID Issuing CA certificate
	// is authorized by IoT Intel(R) EPID Root CA, e.g.,
	// signed by IoT Intel(R) EPID Root CA.
	if (!IsCaCertAuthorizedByRootCa(cacert, sizeof(*cacert))) 
	{
		return EPIDA_ERR;
	}

	return EPIDA_OK;
}

/// Loads a group public key
INT32 LoadGroupKey(CHAR const* filename, GroupPubKey* pub_key)
{
	if (0 != ReadLoud(filename, pub_key, sizeof(*pub_key))) 
	{
		return EPIDA_ERR;
	}

	return EPIDA_OK;
}

/// Loads group certificate
/*!
 *  note this allocates a buffer for signed_pubkey that must be freed
 */
INT32 LoadGroupCert(CHAR const* filename, EpidCaCertificate const* cacert, GroupPubKey* pub_key) 
{
	INT32 result = EPIDA_ERR;
	UCHAR* signed_pubkey = NULL;
	
	do
	{
		EpidStatus sts;
		size_t signed_pubkey_size = 0;

		// detect fopen failure here so we can do custom error msg
		if (!FileExists(filename)) 
		{
			result = EPIDA_ERR;
			break;
		}

		signed_pubkey = NewBufferFromFile(filename, &signed_pubkey_size);
		if (NULL == signed_pubkey)
		{
			result = EPIDA_ERR;
			break;
		}

		// authenticate and extract group public key
		sts = EpidParseGroupPubKeyFile(signed_pubkey, signed_pubkey_size, cacert, pub_key);
		if (kEpidNoErr != sts)
		{
			result = EPIDA_ERR;
			break;
		}
		result = EPIDA_OK;
	} while (0);

	EPIDA_SAFE_FREE(signed_pubkey);

	return result;
}

/// Loads issuer nonce
INT32 LoadIssuerNonce(CHAR const* filename, IssuerNonce* nonce) 
{
	if (0 != ReadLoud(filename, nonce, sizeof(*nonce)))
	{
		return EPIDA_ERR;
	}

	return EPIDA_OK;
}

/// Loads private f
INT32 LoadPrivatef(CHAR const* filename, FpElemStr* privatef)
{
	if (0 != ReadLoud(filename, privatef, sizeof(*privatef)))
	{
		return EPIDA_ERR;
	}

	return EPIDA_OK;
}

/// Configures the bitsupplier
INT32 ConfigureBitsupplier(CHAR const* filename, VOID** rnd_ctx)
{
	if (NULL == rnd_ctx)
	{
		return EPIDA_ERR;
	}

	*rnd_ctx = NewBitSupplier(filename);
	if (NULL == *rnd_ctx)
	{
	    return EPIDA_ERR;
	}

	return EPIDA_OK;
}

INT32 epida_make_join_req(const CHAR* res_directory_path, const CHAR* nonce_file_fullname,
				  const CHAR* passphrase, INT32 passphrase_len, const CHAR* joinreq_file_fullname)
{
    GroupPubKey pub_key = { 0 };
    IssuerNonce nonce = { 0 };
    MemberJoinRequest join_request = { 0 };
	VOID* rnd_ctx = NULL;
	BitSupplier rnd_func = NULL;
    UCHAR is_first_random = 1;
    FpElemStr value_f = {0};
	INT32 ret = EPIDA_ERR;

    /* check input parameters */
	if (NULL == res_directory_path)
	{
		return EPIDA_NO_RES_PATH;
	}

	UINT32 res_dir_path_len = (UINT32)strlen(res_directory_path);
	if ((0 == res_dir_path_len) || (res_dir_path_len > EPIDA_RES_DIR_PATH_MAX))
	{
		return EPIDA_INVALID_RES_PATH_LEN;
	}

	if (NULL == nonce_file_fullname)
	{
		return EPIDA_NO_NI_FILE;
	}

	if ( (NULL == passphrase) || (passphrase_len <= 0) )
	{
		return EPIDA_NO_PASSPHRASE;
	}

    /* step-1: set the full path the meterial to sign message, the directory specified by caller and the filename is fixed value */
	CHAR cacert_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
	CHAR pubkey_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
	snprintf(cacert_file_path, sizeof(cacert_file_path) - 1, "%s%s%s",
		res_directory_path,
		PATH_SLASH,
		CACERT_FILE_NAME);

	snprintf(pubkey_file_path, sizeof(pubkey_file_path) - 1, "%s%s%s",
		res_directory_path,
		PATH_SLASH,
		PUBKEY_FILE_NAME);
    
    // Group
    if (0 != LoadGroupKey(pubkey_file_path, &pub_key))
    {
        EpidCaCertificate cacert = { 0 };
        if (0 != LoadCaCert(cacert_file_path, &cacert))
        {
            return EPIDA_NO_CACER_FILE;
        }
        if (0 != LoadGroupCert(pubkey_file_path, &cacert, &pub_key))
        {
            return EPIDA_NO_PUBKEY_FILE;
        }
    }
    
    // Issuer nonce
    if (0 != LoadIssuerNonce(nonce_file_fullname, &nonce))
    {
        return EPIDA_NO_NI_FILE;
    }
	
    for (; ;)
	{
		ret = ConfigureBitsupplier(NULL, &rnd_ctx);
		if (0 != ret)
		{
			ret = EPIDA_NO_RANDOM_FILE;
			break;
		}

		rnd_func = SupplyBits;
		if (kEpidNoErr != MakeJoinRequest(res_directory_path, &pub_key, &nonce,
			                        &join_request, rnd_func, rnd_ctx, passphrase, passphrase_len,
                                    is_first_random, &value_f))
		{
			ret = EPIDA_MAKE_JOINREQ_FAIL;
			break;
		}
        if (is_first_random)
        {
            memset(&join_request, 0, sizeof(join_request));
            DeleteBitSupplier(&rnd_ctx);
            is_first_random = 0;
            continue;
        }
		
		if (0 != WriteLoud(&join_request, sizeof(join_request), joinreq_file_fullname))
		{
			ret = EPIDA_WRITE_FILE_FAIL;
		}
		
		ret = EPIDA_OK;
        break;
	}

	if (rnd_ctx)
	{
		DeleteBitSupplier(&rnd_ctx);
	}

	return ret;
}
