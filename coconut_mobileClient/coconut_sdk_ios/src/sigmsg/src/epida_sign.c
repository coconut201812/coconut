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
 * \signing message implementation, including:
 *  1) sign a default message with all known basenames in bsn list file.
 *	2) sign a transaction message with a random basename in bsn list file.
*/

/* system header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* epdia common header files */
#include "include/epida_define.h"
#include "util/buffutil.h"

/* current module header files */
#include "sigmsg/epida_crypt.h"
#include "sigmsg/epida_signmsg.h"

/*
* Location to save common resource on mobile client
* The signing meterial resource directory
* resource list:
* 1. EPID Issuing CA certificate and EPID root CA certificate for verifying SigRL, extracting group public key ----cacert.bin
* 2. EPID member private key for signing a message(corresponding to EPID group) ----mprivkey.dat
* 3. EPID group public key in EPID formatted binaray(corresponding to EPID group) ----pubkey.bin
* 4. basename list(corresponding to EPID group)  ---basenames.dat count:seq:len:value
*/

#define CREDENTIAL_FILE_NAME       "epid_credential.dat"
#define NONCE_FILE_NAME            "epid_nonce.dat"
#define TRANSACTION_FILE_NAME      "transaction.dat"

#define DEFAULT_MESSAGE_TEXT       "abcd1234"
#define BASENAME_VALUE_PREFIX      "\"basename\":"
#define BASENAME_VALUE_PREFIX_LEN  (sizeof(BASENAME_VALUE_PREFIX) - 1)
#define BASENAME_COUNT_PREFIX       "\"basenameCount\":"
#define BASENAME_COUNT_PREFIX_LEN   (sizeof(BASENAME_COUNT_PREFIX) - 1)
#define BASENAME_CLOSURE_STR        "\""
#define BASENAME_CLOSURE_STR_LEN    (sizeof(BASENAME_CLOSURE_STR) - 1)
#define BASENAME_COUNT_MAX          (128)


bool IsCaCertAuthorizedByRootCa(VOID const* data, size_t size)
{
	// Implementation of this function is out of scope of the sample.
	// In an actual implementation Issuing CA certificate must be validated
	// with CA Root certificate before using it in parse functions.
	(void)data;
	(void)size;
	return true;
}

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
	
		if ( (0 == bsn_list_size) || (0 != ReadLoud(bsn_list_file, bsn_list_buff, bsn_list_size)) )
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
	if ( (NULL == bsn_list_file) || (NULL == bsn_value_ret) || (NULL == bsn_length_ret) )
	{
		return EPIDA_INVALID_PARAMETERS;
	}

	/* step-1: read all the basenames from basename list file to buffer */
	bsn_list_buff = NewBufferFromFile(bsn_list_file, &bsn_list_size);
	if (!bsn_list_buff)
	{
		return EPIDA_NO_BSN_LIST_FILE;
	}

	if ( (0 == bsn_list_size) || (0 != ReadLoud(bsn_list_file, bsn_list_buff, bsn_list_size)) )
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
    while ( (cur_pos >= bsn_list_buff) && (cur_pos - bsn_list_buff < bsn_list_size) )
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

/* sign a specified message with all the basenames one by one and stored to the signature file */
static INT32 epida_sign_with_basenames(const CHAR* bsn_list_file_path, const CHAR* sig_file_path,
                                       epida_sig_info_t* sig_info)
{
	INT32 bsn_count = 0;
	UINT16 bsn_seq = 0;	
	CHAR* basename = NULL;
	UINT16 basename_len = 0;
	EpidSignature* sig = NULL;
	size_t sig_size = 0;
	EpidStatus epid_ret = kEpidErr;
	INT32 ret = EPIDA_OK;

	/* check input parameters */
	if ( (NULL == bsn_list_file_path) || (NULL == sig_file_path) || (NULL == sig_info) )
	{
		return EPIDA_INVALID_PARAMETERS;
	}

	/* step-1: get the total count of basename in the bsn list file */
	bsn_count = get_bsn_count(bsn_list_file_path);
	if ( (bsn_count <= 0) || (bsn_count >= BASENAME_COUNT_MAX) )
	{
		return EPIDA_INVALID_BSN_LIST;
	}

	UINT16 bsn_seq_start = (UINT16)((sig_info->is_specified_bsn) ? sig_info->specified_bsn_seq % bsn_count : 0);
	UINT16 bsn_seq_end = (UINT16)((sig_info->is_specified_bsn) ? (bsn_seq_start  + 1) : bsn_count);
	for (bsn_seq = bsn_seq_start; bsn_seq < bsn_seq_end; ++bsn_seq)
	{	
		/* step-2: extract a new basename from bsn_list file by the sequence of basename */
        EPIDA_SAFE_FREE(basename);
		basename_len = 0;
		ret = get_one_basename_by_seq(bsn_list_file_path, bsn_seq, &basename, &basename_len);
		if ( (EPIDA_OK != ret) || (NULL == basename) || (0 == basename_len) )
		{
            ret = EPIDA_INVALID_BSN_LIST;
			break;
		}

		/* specify the curr'ent basename to generate a new signature */
		sig_info->basename = basename;
		sig_info->basename_len = basename_len;
        EPIDA_SAFE_FREE(sig);
		sig_size = 0;
		epid_ret = SignMsg(sig_info, &sig, &sig_size);			
		if ( (kEpidNoErr != epid_ret) || (NULL == sig) || (0 == sig_size)  )
		{			
			ret = EPIDA_SINMSG_FAIL;
			break;
		}
		
		/* step-2: store signature to sigs file */
		/* 2.1 sign a transcation */
		if (sig_info->is_specified_bsn) /* if only sign with one basename, return signature buffer directly */
		{
            PrivKey *private_key = (PrivKey*)(sig_info->mprivkey);
            INT32 write_ret;
			write_ret = WriteLoud("@@Basename:", sizeof("@@Basename:") - 1, sig_file_path);
			write_ret += AppendLoud((VOID*)sig_info->basename, sig_info->basename_len, sig_file_path);
			write_ret += AppendLoud("@@", sizeof("@@") - 1, sig_file_path);
            write_ret += AppendLoud("@@groupID:", sizeof("@@groupID:") - 1, sig_file_path);
            write_ret += AppendLoud((VOID*)(&private_key->gid), sizeof(private_key->gid), sig_file_path);
            write_ret += AppendLoud("@@", sizeof("@@") - 1, sig_file_path);
			write_ret += AppendLoud(sig, sig_size, sig_file_path);
            if (0 != write_ret)
			{
				ret = EPIDA_WRITE_FILE_FAIL;
				break;
			}

			break;
		}
		
		/* 2.2 make all signatures by basename list */
		if (0 == bsn_seq)
		{
			CHAR sig_count_str[128] = { 0 };
			snprintf(sig_count_str, sizeof(sig_count_str) - 1, "@@SigCount:%u@@\n", bsn_seq_end);
			if (0 != WriteLoud(sig_count_str, strlen(sig_count_str), sig_file_path))
			{
				ret = EPIDA_WRITE_FILE_FAIL;
				break;
			}
		}
	
		CHAR sig_seq_str[64] = { 0 };
		snprintf(sig_seq_str, sizeof(sig_seq_str) - 1, "@@SigNo:%u@@", bsn_seq + 1);
		if (0 != AppendLoud(sig_seq_str, strlen(sig_seq_str), sig_file_path))
		{
			ret = EPIDA_WRITE_FILE_FAIL;
			break;
		}
		if (0 != AppendLoud(sig, sig_size, sig_file_path))
		{
			ret = EPIDA_WRITE_FILE_FAIL;
			break;
		}
	}
	
	/* step-3: cleanup temporary resource */
    EPIDA_SAFE_FREE(basename);
    EPIDA_SAFE_FREE(sig);

	return ret;
}

/* make a sign file including all signatures corresponding to different basename */
INT32 epida_make_sign_file(const CHAR* res_directory_path, const UCHAR* passphrase,
                           INT32 passphrase_len, const CHAR* all_sigs_file_fullname)
{
	/* User Settings */
	/* the meterial used to sign a message */
	// 1.1 CA certificate
	EpidCaCertificate cacert = {0};
  
	// 1.2 Group public key file
	UCHAR* pub_key = NULL;
	size_t pubkey_size = 0;
  
	// 1.3 Member private key buffer
    UCHAR* cipher_mprivkey = NULL;
    size_t cipher_mprivkey_len = 0;
	UCHAR* mprivkey = NULL;
	INT32 mprivkey_size = 0;

	// 1.4 Member pre-computed settings
	MemberPrecomp* member_precmp = NULL;

	// 1.5 SigRl file
	UCHAR* signed_sig_rl = NULL;
	size_t signed_sig_rl_size = 0;
	epida_sig_info_t sig_info = { 0 };

	INT32 ret = EPIDA_ERR;

	/* check input parameters */
	if (NULL == res_directory_path)
	{
		return EPIDA_NO_RES_PATH;
	}

	if (NULL == all_sigs_file_fullname)
	{
		return EPIDA_NO_BSN_SIG_FILE_PATH;
	}

    if ( (NULL == passphrase) || (passphrase_len <= 0) )
    {
        return EPIDA_NO_PASSPHRASE;
    }

	UINT32 res_directory_path_len = (UINT32)strlen(res_directory_path);
	if ( (0 == res_directory_path_len) || (res_directory_path_len > EPIDA_RES_DIR_PATH_MAX) )
	{
		return EPIDA_INVALID_RES_PATH_LEN;
	}

 	do
	{
        CHAR res_file_full_path[EPIDA_FILE_PATH_MAX] = { 0 };

		/* step-1: prepare the meterial to sign message */
		// 1.1: get CA certificate from the EPID certificate file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 CACERT_FILE_NAME);
		if (FileExists(res_file_full_path))
		{
			if (0 != ReadLoud(res_file_full_path, &cacert, sizeof(cacert)))
			{
				ret = EPIDA_INVALID_CACER;
				break;
			}
		}

		// 1.2 get sigRl from the EPID sigRl file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 SIG_RL_FILE_NAME);
        if (FileExists(res_file_full_path))
		{
			signed_sig_rl = NewBufferFromFile(res_file_full_path, &signed_sig_rl_size);
			if (NULL == signed_sig_rl)
			{
				ret = EPIDA_READ_FILE_FAIL;
				break;
			}

			if (0 != ReadLoud(res_file_full_path, signed_sig_rl, signed_sig_rl_size))
			{
				ret = EPIDA_READ_FILE_FAIL;
				break;
			}
		}
      
		// 1.3 get group public key from EPID public key file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 PUBKEY_FILE_NAME);
		pub_key = NewBufferFromFile(res_file_full_path, &pubkey_size);
		if (NULL == pub_key)
		{
			ret = EPIDA_NO_PUBKEY_FILE;
			break;
		}
		if (0 != ReadLoud(res_file_full_path, pub_key, pubkey_size))
		{
			ret = EPIDA_READ_FILE_FAIL;
			break;
		}

		// 1.4: get member private key from EPID member private key file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 MPRIVKEY_FILE_NAME);
		cipher_mprivkey = NewBufferFromFile(res_file_full_path, &cipher_mprivkey_len);
		if (NULL == cipher_mprivkey)
		{
			ret = EPIDA_NO_PRIVKEY_FILE;
			break;
		}
        if (0 != ReadLoud(res_file_full_path, cipher_mprivkey, cipher_mprivkey_len))
        {
            ret = EPIDA_READ_FILE_FAIL;
            break;
        }
        mprivkey_size = (INT32)cipher_mprivkey_len;
        mprivkey = do_decrypt((UCHAR*)passphrase, passphrase_len, cipher_mprivkey , &mprivkey_size);
        if ( (NULL == mprivkey) || (0 == mprivkey_size) )
        {
            ret = EPIDA_DECRYPT_FAIL;
            break;
        }

		/* find out the type of member private key in three known types */
		if (mprivkey_size != sizeof(PrivKey))
		{
			ret = EPIDA_INVALID_PRIVKEY;
			break;
		}

		// 1.5 Load Member pre-computed settings to enhance performance for verifying
    
		/* step-2: sign message with all basenames one by one, and write every signature to the corresponding signature file */
		sig_info.msg = DEFAULT_MESSAGE_TEXT;  /* sign default message text when signed with all basenames */
		sig_info.msg_len = sizeof(DEFAULT_MESSAGE_TEXT) - 1;
		sig_info.cacert = &cacert;
		sig_info.gpubkey = pub_key;  /* group public key from pubkey.bin signed by issuing CA certificate */
		sig_info.gpubkey_size = pubkey_size;
		sig_info.mprivkey = mprivkey;
		sig_info.mprivkey_size = mprivkey_size;
		sig_info.basename = NULL;
		sig_info.basename_len = 0;
		sig_info.signed_sig_rl = signed_sig_rl; /* SigRl from sigrl.bin signed by issuing CA certificate */
		sig_info.signed_sig_rl_size = signed_sig_rl_size;
		sig_info.member_precomp = member_precmp;
		sig_info.is_specified_bsn = 0;
		sig_info.specified_bsn_seq = 0;
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 BASENAME_LIST_FILE_NAME);
		if (EPIDA_OK != (ret = epida_sign_with_basenames(res_file_full_path, all_sigs_file_fullname, &sig_info)))
		{
			break;
		}

		//make all signatures with all basenames one by one successfully
		ret = EPIDA_OK;
	} while (0);

	/* step-3: cleanup all temporary resource(including allocated memory etc..) */
    EPIDA_SAFE_FREE(signed_sig_rl);
    EPIDA_SAFE_FREE(pub_key);
    EPIDA_SAFE_FREE(cipher_mprivkey);
    EPIDA_SAFE_CLEANUP(mprivkey, mprivkey_size);

	return ret;
}

/* sign transaction with a random specified basename in the bsn list file */
INT32 epida_sign_transaction(const CHAR* res_directory_path, const UCHAR* passphrase, INT32 passphrase_len,
         const CHAR* transaction_file_fullname, const CHAR* signature_file_fullname)
{
	/* User Settings */
	/* 1. the meterial used to sign a message */
	// 1.1 CA certificate
	EpidCaCertificate cacert = { 0 };

	// 1.2 Group public key file
	UCHAR* gpubkey = NULL;
	size_t gpubkey_size = 0;

	// 1.3 Member private key buffer
    UCHAR* cipher_mprivkey = NULL;
    size_t cipher_mprivkey_len = 0;
	UCHAR* mprivkey = NULL;
	INT32 mprivkey_size = 0;

	// 1.4 Member pre-computed settings
	MemberPrecomp* member_precmp = NULL;

	// 1.5 SigRl file
	UCHAR* signed_sig_rl = NULL;
	size_t signed_sig_rl_size = 0;

	/* 2. the message to be signed */
	// Message string parameter
	VOID* msg_to_be_signed = NULL;
	size_t msg_size = 0;
	
	static UINT32 specified_bsn_seq = 0;
	epida_sig_info_t sig_info = { 0 };

	INT32 ret = EPIDA_ERR;

	/* check input parameters */
	if (NULL == res_directory_path)
	{
		return EPIDA_NO_RES_PATH;
	}

    if ( (NULL == passphrase) || (passphrase_len <= 0) )
    {
        return EPIDA_NO_PASSPHRASE;
    }
	
	if (NULL == transaction_file_fullname)
	{
		return EPIDA_NO_TRANS_FILE_PATH;
	}

	if (NULL == signature_file_fullname)
	{
		return EPIDA_NO_TRANSC_SIG_PATH;
	}

	UINT32 res_dir_path_len = (UINT32)strlen(res_directory_path);
	if ( (0 == res_dir_path_len) || (res_dir_path_len > EPIDA_RES_DIR_PATH_MAX) )
	{
		return EPIDA_INVALID_RES_PATH_LEN;
	}

	/* get the transaction as a message to be signed */
	if (!FileExists(transaction_file_fullname))
	{
		return EPIDA_NO_TRANS_FILE;
	}
	msg_to_be_signed = NewBufferFromFile(transaction_file_fullname, &msg_size);
	if (NULL == msg_to_be_signed)
	{
		return EPIDA_NO_TRANS_FILE;
	}
	if (0 != ReadLoud(transaction_file_fullname, msg_to_be_signed, msg_size))
	{
		EPIDA_SAFE_FREE(msg_to_be_signed);
		return EPIDA_NO_TRANS_FILE;
	}
	
	do
	{
        CHAR res_file_full_path[EPIDA_FILE_PATH_MAX] = { 0 };
		
		/* step-1: get the meterial to sign message */
		// 1.1: get CA certificate from the EPID certificate file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 CACERT_FILE_NAME);
        if (FileExists(res_file_full_path))
        {
            if (0 != ReadLoud(res_file_full_path, &cacert, sizeof(cacert)))
            {
                ret = EPIDA_INVALID_CACER;
                break;
            }
        }

		// 1.2 get sigRl from the EPID sigRl file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 SIG_RL_FILE_NAME);
		if (FileExists(res_file_full_path))
		{
			signed_sig_rl = NewBufferFromFile(res_file_full_path, &signed_sig_rl_size);
			if (!signed_sig_rl)
			{
				ret = EPIDA_READ_FILE_FAIL;
				break;
			}

			if (0 != ReadLoud(res_file_full_path, signed_sig_rl, signed_sig_rl_size))
			{
				ret = EPIDA_READ_FILE_FAIL;
				break;
			}
		}

		// 1.3 get group public key from EPID public key file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 PUBKEY_FILE_NAME);
		gpubkey = NewBufferFromFile(res_file_full_path, &gpubkey_size);
		if (!gpubkey)
		{
			ret = EPIDA_NO_PUBKEY_FILE;
			break;
		}
		if (0 != ReadLoud(res_file_full_path, gpubkey, gpubkey_size))
		{
			ret = EPIDA_READ_FILE_FAIL;
			break;
		}

		// 1.4: get member private key from EPID member private key file
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 MPRIVKEY_FILE_NAME);
        cipher_mprivkey = NewBufferFromFile(res_file_full_path, &cipher_mprivkey_len);
        if (NULL == cipher_mprivkey)
        {
            ret = EPIDA_NO_PRIVKEY_FILE;
            break;
        }
        if (0 != ReadLoud(res_file_full_path, cipher_mprivkey, cipher_mprivkey_len))
        {
            ret = EPIDA_READ_FILE_FAIL;
            break;
        }
        mprivkey_size = (INT32)cipher_mprivkey_len;
        mprivkey = do_decrypt((UCHAR*)passphrase, passphrase_len, cipher_mprivkey , &mprivkey_size);
        if ( (NULL == mprivkey) || (0 == mprivkey_size) )
        {
            ret = EPIDA_DECRYPT_FAIL;
            break;
        }

		/* find out the type of member private key in three known types */
		if (mprivkey_size != sizeof(PrivKey))
		{
			ret = EPIDA_INVALID_PRIVKEY;
			break;
		}

		/* step-2: sign the transaction and generate a signature file */
        snprintf(res_file_full_path, sizeof(res_file_full_path) - 1, "%s%s%s",
                 res_directory_path,
                 PATH_SLASH,
                 BASENAME_LIST_FILE_NAME);
		sig_info.msg = msg_to_be_signed;
		sig_info.msg_len = msg_size;
		sig_info.cacert = &cacert;
		sig_info.gpubkey = gpubkey;  /* group public key from pubkey.bin signed by issuing CA certificate */
		sig_info.gpubkey_size = gpubkey_size;
		sig_info.mprivkey = mprivkey;
		sig_info.mprivkey_size = mprivkey_size;
		sig_info.basename = NULL;
		sig_info.basename_len = 0;
		sig_info.signed_sig_rl = signed_sig_rl; /* SigRl from sigrl.bin signed by issuing CA certificate */
		sig_info.signed_sig_rl_size = signed_sig_rl_size;
		sig_info.member_precomp = member_precmp;
		sig_info.is_specified_bsn = 1;
		sig_info.specified_bsn_seq = ++specified_bsn_seq;
		if (EPIDA_OK != (ret = epida_sign_with_basenames(res_file_full_path, signature_file_fullname, &sig_info)))
		{
			break;
		}

		//Succeed to get the signature to sign a specified transaction
		ret = EPIDA_OK;
	} while (0);

	/* step-3: cleanup all temporary resource(including allocated memory etc..) */
    EPIDA_SAFE_FREE(signed_sig_rl);
    EPIDA_SAFE_FREE(gpubkey);
    EPIDA_SAFE_FREE(cipher_mprivkey);
    EPIDA_SAFE_FREE(msg_to_be_signed);
    EPIDA_SAFE_CLEANUP(mprivkey, mprivkey_size);

	return ret;
}
