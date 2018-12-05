/*!
 * \file
 * \brief Signature verification implementation.
 */

/* system header files */
#include <stdlib.h>
#include <string.h>

/* epdia common header files */
#include "include/epida_define.h"
#include "util/buffutil.h"
#include "util/convutil.h"
#include "util/envutil.h"
#include "epid/common/file_parser.h"
#include "epid/verifier/api.h"

/* current module header files */
#include "epida_verifysig.h"


#define BASENAME_VALUE_PREFIX      "\"basename\":"
#define BASENAME_VALUE_PREFIX_LEN  (sizeof(BASENAME_VALUE_PREFIX) - 1)
#define BASENAME_COUNT_PREFIX       "\"basenameCount\":"
#define BASENAME_COUNT_PREFIX_LEN   (sizeof(BASENAME_COUNT_PREFIX) - 1)
#define BASENAME_CLOSURE_STR        "\""
#define BASENAME_CLOSURE_STR_LEN    (sizeof(BASENAME_CLOSURE_STR) - 1)
#define BASENAME_COUNT_MAX          (128)


/* get the total count of the basename in the bsn list file */
static INT32 get_bsn_count(const CHAR* bsn_list_file)
{
	CHAR* bsn_list_buff = NULL;
	size_t bsn_list_size = 0;
	INT32 bsn_count = 0;

	/* check input parameters */
	do
	{
		if (NULL == bsn_list_file)
		{
			break;
		}

		/* step-1: read all the basenames from basename list file to buffer */
		bsn_list_buff = NewBufferFromFile(bsn_list_file, &bsn_list_size);
		if (!bsn_list_buff)
		{
			break;
		}

		if ((0 == bsn_list_size) || (0 != ReadLoud(bsn_list_file, bsn_list_buff, bsn_list_size)))
		{
			break;
		}
		bsn_list_buff[bsn_list_size - 1] = '\0';

		/* step-2: parse bsn list file to get the total count of basename */
		/*
		* basename list file format like this:
		{
		"basenameCount":"10",
		"basenames":
		[
		{"basename":"0"},
		{"basename":"1"},
		{"basename":"2"},
		{"basename":"3"},
		{"basename":"4"},
		{"basename":"5"},
		{"basename":"6"},
		{"basename":"7"},
		{"basename":"8"},
		{"basename":"9"}
		]
		}
		*/
		CHAR* temp_str = strstr(bsn_list_buff, BASENAME_COUNT_PREFIX);
		if (NULL != temp_str)
		{
			CHAR* bsn_count_start = strstr(temp_str + BASENAME_COUNT_PREFIX_LEN, BASENAME_CLOSURE_STR);
			CHAR* bsn_count_end = NULL;
			if (NULL != bsn_count_start)
			{
				bsn_count_end = strstr(bsn_count_start + BASENAME_CLOSURE_STR_LEN, BASENAME_CLOSURE_STR);
				if (NULL != bsn_count_end)
				{
					*bsn_count_end = '\0';
					bsn_count_start += BASENAME_CLOSURE_STR_LEN;  /* skip the basename closure string */
					bsn_count = atoi(bsn_count_start); /* success, got the basename count */
				}
			}
		}
	} while (0);

	EPIDA_SAFE_FREE(bsn_list_buff);

	return bsn_count;
}

/* get one basename by the specified sequence */
static INT32 get_one_basename_by_seq(const CHAR* bsn_list_file, UINT16 bsn_sequence,
	CHAR** bsn_value_ret, UINT16* bsn_length_ret)
{
	CHAR* bsn_list_buff;
	size_t bsn_list_size = 0;
	UINT16 cur_bsn_sequence = 0;
	UINT16 cur_bsn_len = 0;
	CHAR* found_bsn = NULL;
	UINT16 found_bsn_len = 0;
	INT32 ret = EPIDA_ERR;

	/* check input parameters */
	if ((NULL == bsn_list_file) || (NULL == bsn_value_ret) || (NULL == bsn_length_ret))
	{
		return EPIDA_INVALID_PARAMETERS;
	}

	/* step-1: read all the basenames from basename list file to buffer */
	bsn_list_buff = NewBufferFromFile(bsn_list_file, &bsn_list_size);
	if (!bsn_list_buff)
	{
		return EPIDA_NO_BSN_LIST_FILE;
	}

	if ((0 == bsn_list_size) || (0 != ReadLoud(bsn_list_file, bsn_list_buff, bsn_list_size)))
	{
		free(bsn_list_buff);
		return EPIDA_INVALID_BSN_LIST;
	}

	bsn_list_buff[bsn_list_size - 1] = '\0';

	/* step-2: parse the basenames in the buffer to get the basename with specified sequence */
	/*
	* basename list file format like this:
	{
	"basenameCount": "10",
	"basenames":
	[
	{"basename":"0"},
	{"basename":"1"},
	{"basename":"2"},
	{"basename":"3"},
	{"basename":"4"},
	{"basename":"5"},
	{"basename":"6"},
	{"basename":"7"},
	{"basename":"8"},
	{"basename":"9"}
	]
	}
	*/

	CHAR* basename_prefix = NULL;
	CHAR* basename_start = NULL;
	CHAR* basename_end = NULL;
	CHAR* cur_pos = bsn_list_buff;
	while ((cur_pos >= bsn_list_buff) && (cur_pos - bsn_list_buff < bsn_list_size))
	{
		basename_prefix = strstr(cur_pos, BASENAME_VALUE_PREFIX);
		if (NULL == basename_prefix)
		{
			ret = EPIDA_INVALID_BSN_LIST;
			break;
		}

		basename_start = strstr(basename_prefix + BASENAME_VALUE_PREFIX_LEN, BASENAME_CLOSURE_STR);
		if (NULL == basename_start)
		{
			ret = EPIDA_INVALID_BSN_LIST;
			break;
		}

		basename_start += BASENAME_CLOSURE_STR_LEN;  /* skip the basename closure */
		basename_end = strstr(basename_start, BASENAME_CLOSURE_STR);
		if (NULL == basename_end)
		{
			ret = EPIDA_INVALID_BSN_LIST;
			break;
		}

		if (cur_bsn_sequence == bsn_sequence)
		{
			*basename_end = '\0';  /* trim the basename closure */
			cur_bsn_len = (UINT16)strlen(basename_start);
			found_bsn = malloc(cur_bsn_len);
			if (!found_bsn)
			{
				ret = EPIDA_ERR;
				break;
			}

			memcpy(found_bsn, basename_start, cur_bsn_len);
			found_bsn_len = cur_bsn_len;
			ret = EPIDA_OK;
			break;
		}

		++cur_bsn_sequence; /* continue to match next basename */
		cur_pos = basename_end;
	}

	*bsn_value_ret = found_bsn;
	*bsn_length_ret = found_bsn_len;
	EPIDA_SAFE_FREE(bsn_list_buff);

	/* the found basename:bsn_value_ret will be freed after use by caller */
	return ret;
}

/* set all allowed basenames for verifier to verify signature */
static INT32 epida_set_verifier_basenames(VerifierCtx* ctx, const CHAR* bsn_list_file_path, const CHAR* sig_basename, UINT16 sig_basename_len)
{
	INT32 bsn_count = 0;
	UINT16 bsn_seq = 0;
	CHAR* basename = NULL;
	UINT16 basename_len = 0;	
	INT32 ret = EPIDA_OK;

	/* check input parameters */
	if ( (NULL == bsn_list_file_path) || (NULL == ctx) || (NULL == sig_basename) || (0 == sig_basename_len) )
	{
		return EPIDA_INVALID_PARAMETERS;
	}	

	/* step-1: get the total count of basename in the bsn list file */
	bsn_count = get_bsn_count(bsn_list_file_path);
	if ((bsn_count <= 0) || (bsn_count >= BASENAME_COUNT_MAX))
	{
		return EPIDA_INVALID_BSN_LIST;
	}
	
	for (bsn_seq = 0; bsn_seq < bsn_count; ++bsn_seq)
	{
		/* step-2: extract a new basename from bsn_list file by the sequence of basename */
		if (NULL != basename)
		{
			free(basename);
			basename = NULL;
		}

		basename_len = 0;
		ret = get_one_basename_by_seq(bsn_list_file_path, bsn_seq, &basename, &basename_len);
		if ((EPIDA_OK != ret) || (NULL == basename) || (0 == basename_len))
		{
			break;
		}

		/* set the current basename to basename list allowed by verifier */
		if ((sig_basename_len == basename_len) && (0 == memcmp(sig_basename, basename, basename_len)))
		{
			if (kEpidNoErr != EpidVerifierSetBasename(ctx, basename, basename_len))
			{
				ret = EPIDA_SET_VERIFIER_BSN_FAIL;
			}
			break;
		}
	}

	/* step-3: cleanup temporary resource */
	EPIDA_SAFE_FREE(basename);
	
	return ret;
}

EpidStatus Verify(verify_info_t* verify_info, EpidSignature const* sig, size_t sig_len, void const* msg, size_t msg_len)
{
	EpidStatus result = EPIDA_OK;
	VerifierCtx* ctx = NULL;
	PrivRl* priv_rl = NULL;
	SigRl* sig_rl = NULL;
	GroupRl* grp_rl = NULL;

	/* check input parameters */
	if ( (NULL == verify_info) || (NULL == sig) || (NULL == msg) || (0 == sig_len) || (0 == msg_len) )
	{
		return EPIDA_INVALID_PARAMETERS;
	}

    do
	{
		/* step-1: retrieve the verifier meterial signed by Issuing CA certificate */
		GroupPubKey pub_key = {0};
	
		// 1.1 authenticate and extract group public key
		if (verify_info->signed_pub_key_size != sizeof(GroupPubKey))
		{
			if (kEpidNoErr != EpidParseGroupPubKeyFile(verify_info->signed_pub_key, verify_info->signed_pub_key_size,
				verify_info->cacert, &pub_key))
			{
				result = EPIDA_INVALID_PUBKEY;
				break;
			}
		}
		else
		{
			pub_key = *((GroupPubKey*)verify_info->signed_pub_key);
		}
		

		// 1.2 ensure the pre-computation blob is not in a legacy format
		if ( (NULL != *verify_info->verifier_precomp)
			    && (*(verify_info->verifier_precomp_size) != sizeof(VerifierPrecomp)) )
		{
			result = EPIDA_SET_VERIFIER_CTX_FAIL;
			break;
		}
		*(verify_info->verifier_precomp_size) = sizeof(VerifierPrecomp);

		// step-2: create verifier and set verifier context
		if (kEpidNoErr != EpidVerifierCreate(&pub_key, *verify_info->verifier_precomp, &ctx))
		{
			result = EPIDA_SET_VERIFIER_CTX_FAIL;
			break;
		}

		// 2.1 serialize verifier pre-computation blob
		if (NULL == *verify_info->verifier_precomp) 
		{
			*(verify_info->verifier_precomp) = calloc(1, *verify_info->verifier_precomp_size);
		}

		if (kEpidNoErr != EpidVerifierWritePrecomp(ctx, *verify_info->verifier_precomp))
		{
			result = EPIDA_SET_VERIFIER_CTX_FAIL;
			break;
		}
				
		// 2.2 set the basenames allowed by verifier
		if (EPIDA_OK != (result = epida_set_verifier_basenames(ctx, verify_info->basename_list_file_fullname, verify_info->basename, (UINT16)verify_info->basename_size)))
		{
			break;
		}

		/* 2.3 set member private key Rl */
		if (verify_info->signed_priv_rl)
		{
			// authenticate and determine space needed for RL
			size_t priv_rl_size = 0;
			if (kEpidNoErr != EpidParsePrivRlFile(verify_info->signed_priv_rl, verify_info->signed_priv_rl_size,
				          verify_info->cacert, NULL, &priv_rl_size) )
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			priv_rl = calloc(1, priv_rl_size);
			if (NULL == priv_rl)
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			// fill the rl
			if (kEpidNoErr != EpidParsePrivRlFile(verify_info->signed_priv_rl, verify_info->signed_priv_rl_size,
				         verify_info->cacert, priv_rl, &priv_rl_size) )
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			// set private key based revocation list
			if (kEpidNoErr != EpidVerifierSetPrivRl(ctx, priv_rl, priv_rl_size))
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}
		}

		/* 2.4 set signature Rl */
		if (NULL != verify_info->signed_sig_rl) 
		{
			// authenticate and determine space needed for RL
			size_t sig_rl_size = 0;
			if (kEpidNoErr != EpidParseSigRlFile(verify_info->signed_sig_rl, verify_info->signed_sig_rl_size,
				            verify_info->cacert, NULL, &sig_rl_size) )
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			sig_rl = calloc(1, sig_rl_size);
			if (NULL == sig_rl)
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			// fill the rl
			if ( kEpidNoErr != EpidParseSigRlFile(verify_info->signed_sig_rl, verify_info->signed_sig_rl_size,
				          verify_info->cacert, sig_rl, &sig_rl_size) )
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			// set signature based revocation list
			if (kEpidNoErr != EpidVerifierSetSigRl(ctx, sig_rl, sig_rl_size))
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}
		}

		/* 2.5 set group Rl */
		if (verify_info->signed_grp_rl)
		{
			// authenticate and determine space needed for RL
			size_t grp_rl_size = 0;
			if ( kEpidNoErr != EpidParseGroupRlFile(verify_info->signed_grp_rl, verify_info->signed_grp_rl_size,
				          verify_info->cacert, NULL, &grp_rl_size) )
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			grp_rl = calloc(1, grp_rl_size);
			if (NULL == grp_rl)
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}
			
			// fill the rl
			if (kEpidNoErr != EpidParseGroupRlFile(verify_info->signed_grp_rl, verify_info->signed_grp_rl_size,
				           verify_info->cacert, grp_rl, &grp_rl_size))
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}

			// set group revocation list
			if (kEpidNoErr != EpidVerifierSetGroupRl(ctx, grp_rl, grp_rl_size))
			{
				result = EPIDA_SET_VERIFIER_CTX_FAIL;
				break;
			}
		}
				
		// verify signature
		if (kEpidNoErr != EpidVerify(ctx, sig, sig_len, msg, msg_len))
		{
			result = EPIDA_VERIFY_SIG_FAIL;
			break;
		}
	} while (0);

	/* step-4: cleanup temporary resources */
	//delete verifier
	EpidVerifierDelete(&ctx);

	EPIDA_SAFE_FREE(priv_rl);
	EPIDA_SAFE_FREE(sig_rl);
	EPIDA_SAFE_FREE(grp_rl);

	return result;
}
