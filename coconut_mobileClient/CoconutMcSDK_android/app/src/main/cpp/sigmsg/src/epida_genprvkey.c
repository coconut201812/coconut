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
 * \generate a member private key implementation:
 *  1) generate a f value by users;
 *  2) generate a member private key according to the f value and the membership credetial.
 */

/* system header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* epdia common header files */
#include "include/epida_define.h"
#include "util/buffutil.h"

/* current module header files */
#include "sigmsg/epida_signmsg.h"
#include "sigmsg/epida_crypt.h"


/* generate member private key by public part and local private part */
INT32 epida_generate_prvkey(const CHAR* res_directory_path, const CHAR* credential_file_fullname,
							const UCHAR* passphrase, INT32 passphrase_len)
{
	VOID* credential = NULL;
	size_t credential_size = 0;
    UCHAR* cipher_privf = NULL;
    size_t cipher_privf_len = 0;
	VOID* privatef = NULL;
	INT32 privatef_size = 0;
    UCHAR* cipher_privkey = NULL;
    INT32 cipher_privkey_len = 0;
	PrivKey private_key = { 0 };
    INT32 ret = EPIDA_OK;

    /* check the input parameters */
	if (NULL == res_directory_path)
	{
		return EPIDA_NO_RES_PATH;
	}

	UINT32 res_dir_path_len = (UINT32)strlen(res_directory_path);
	if ((0 == res_dir_path_len) || (res_dir_path_len > EPIDA_RES_DIR_PATH_MAX))
	{
		return EPIDA_INVALID_RES_PATH_LEN;
	}

    if ( (NULL == credential_file_fullname) || (0 == strlen(credential_file_fullname)) )
    {
        return EPIDA_NO_CREDENTIAL_FILE_PATH;
    }    

    if (!FileExists(credential_file_fullname))
    {
        return EPIDA_NO_CREDENTIAL_FILE;
    }

    if ( (NULL == passphrase) || (passphrase_len <= 0) )
    {
        return EPIDA_NO_PASSPHRASE;
    }

	CHAR privatef_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
	CHAR mprivkey_file_path[EPIDA_FILE_PATH_MAX] = { 0 };

	snprintf(privatef_file_path, sizeof(privatef_file_path) - 1, "%s%s%s",
		res_directory_path,
		PATH_SLASH,
		PRIVATEF_FILE_NAME);

	snprintf(mprivkey_file_path, sizeof(mprivkey_file_path) - 1, "%s%s%s",
		res_directory_path,
		PATH_SLASH,
		MPRIVKEY_FILE_NAME);

	do
	{
		/* step-2: get credential, a part of the private key */
		credential = NewBufferFromFile(credential_file_fullname, &credential_size);
		if (NULL == credential)
		{
			ret = EPIDA_NO_CREDENTIAL_FILE;
			break;
		}
		if (0 != ReadLoud(credential_file_fullname, credential, credential_size))
		{
			ret = EPIDA_READ_FILE_FAIL;
			break;
		}
		if (credential_size != sizeof(MembershipCredential))
		{
			ret = EPIDA_INVALID_CREDENTIAL;
			break;
		}

		/* step-3: get privatef */
		cipher_privf = NewBufferFromFile(privatef_file_path, &cipher_privf_len);
		if (NULL == cipher_privf)
		{
			ret = EPIDA_NO_PRIVATEF_FILE;
			break;
		}
		if (0 != ReadLoud(privatef_file_path, cipher_privf, cipher_privf_len))
		{
			ret = EPIDA_READ_FILE_FAIL;
			break;
		}

        privatef_size = (INT32)cipher_privf_len;
        privatef = do_decrypt((UCHAR*)passphrase, passphrase_len, cipher_privf, &privatef_size);
        if ( (NULL == privatef) || (0 == privatef_size) )
        {
            ret = EPIDA_DECRYPT_FAIL;
            break;
        }
		if (privatef_size != sizeof(private_key.f))
		{
			ret = EPIDA_INVALID_PRIVATEF;
			break;
		}

		/* step-4: generate the private key */
		(VOID)memcpy(&private_key, credential, credential_size);
        (VOID)memcpy(&private_key.f, privatef, privatef_size);

        cipher_privkey_len = (INT32)sizeof(private_key);
        cipher_privkey = do_encrypt((UCHAR*)passphrase, passphrase_len, (UCHAR*)&private_key , &cipher_privkey_len);
        if ( (NULL == cipher_privkey) || (0 == cipher_privkey_len) )
        {
            ret = EPIDA_ENCRYPT_FAIL;
            break;
        }

		if (0 != WriteLoud((VOID*)cipher_privkey, cipher_privkey_len, mprivkey_file_path))
		{
			ret = EPIDA_GEN_MEMBERKEY_FAIL;
			break;
		}
	}while (0);

	/* cleanup all temporary resources */
	(VOID)memset(&private_key, 0, sizeof(private_key));
    EPIDA_SAFE_FREE(credential);
    EPIDA_SAFE_FREE(cipher_privf);
    EPIDA_SAFE_CLEANUP(privatef, privatef_size);
    EPIDA_SAFE_FREE(cipher_privkey);

    return ret;
}

