/*!
 * \file
 * \brief Verifysig example implementation.
 */

/* system header files */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* epida common files */
#include "epid/common/file_parser.h"
#include "epid/verifier/api.h"
#include "epida_verifysig.h"
#include "util/buffutil.h"
#include "util/convutil.h"
#include "include/epida_define.h"

/*
* location to save common resource on wallet frontend
* file path: 1)public file path; 2)secret file path(member private key)
* resource list:
* 1. EPID Issuing CA certificate and EPID root CA certificate for verifying SigRL, extracting group public key ----cacert.bin
* 2. EPID member private key for signing a message(corresponding to EPID group) ----mprivkey.dat
* 3. EPID group public key in EPID formatted binaray(corresponding to EPID group) ----pubkey.bin
* 4. basename list(corresponding to EPID group)  ---basenames.dat count:seq:len:value
*/
#define CACERT_FILE_NAME          "epid_cacert.bin"
#define PUBKEY_FILE_NAME          "epid_pubkey.bin"
#define BASENAME_LIST_FILE_NAME   "epid_basenames.dat"

#define GRP_RL_FILE_NAME          "epid_grprl.bin"
#define PRIV_RL_FILE_NAME         "epid_privrl.bin"
#define SIG_RL_FILE_NAME          "epid_sigrl.bin"
#define VER_RL_FILE_NAME          "epid_verrl.dat"

#define EPIDA_FILE_PATH_MAX       (512)
#define EPIDA_RES_DIR_PATH_MAX    (384)
#define PATH_SLASH                "/"


bool IsCaCertAuthorizedByRootCa(void const* data, size_t size) {
  // Implementation of this function is out of scope of the sample.
  // In an actual implementation Issuing CA certificate must be validated
  // with CA Root certificate before using it in parse functions.
  (void)data;
  (void)size;
  return true;
}

INT32 verify_sig(const CHAR *res_directory_path, const CHAR* sig_file_fullname, const CHAR* msg_file_fullname, const CHAR* basename)
{	
	INT32 ret = EPIDA_OK;
	EpidStatus result = kEpidErr;

	// User Settings
	/* 1. the meterial to verify signature */
	// 1.1 CA certificate
	EpidCaCertificate cacert = { 0 };
  
	// 1.2 Group public key buffer
	VOID* pub_key = NULL;
	size_t pubkey_size = 0;
  
	/* 2  Buffers and computed values */
	// PrivRl buffer
	VOID* signed_priv_rl = NULL;
	size_t signed_priv_rl_size = 0;

	// SigRl buffer
	VOID* signed_sig_rl = NULL;
	size_t signed_sig_rl_size = 0;

	// GrpRl buffer
	VOID* signed_grp_rl = NULL;
	size_t signed_grp_rl_size = 0;

	// VerRl buffer
	VerifierRl* ver_rl = NULL;
	size_t ver_rl_size = 0;

	// Verifier pre-computed settings
	VOID* verifier_precomp = NULL;	
	size_t vprecomp_file_size = 0;

	/* 3 data to be verified */
	//3.1 message, passed by caller
	VOID* msg = NULL;
	size_t msg_size = 0;
	
	//3.2 signature, passed by caller
	VOID* sig = NULL;
	size_t sig_size = 0;

	verify_info_t verify_info = {0};

	/* check input parameters */	
	if (NULL == res_directory_path)
	{
		return EPIDA_NO_RES_PATH;
	}

	if (NULL == sig_file_fullname)
	{
		return EPIDA_NO_SIG_FILE_PATH;
	}

	if (NULL == msg_file_fullname)
	{
		return EPIDA_NO_MSG_FILE_PATH;
	}

	if ( (NULL == basename) || (0 == strlen(basename)) )
	{
		return EPIDA_NO_VERIFY_BASENAME;
	}

	UINT32 res_dir_path_len = (UINT32)strlen(res_directory_path);
	if ( (0 == res_dir_path_len) || (res_dir_path_len > EPIDA_RES_DIR_PATH_MAX) )
	{
		return EPIDA_INVALID_RES_PATH_LEN;
	}

	do
	{
		EpidVersion epid_version = kNumEpidVersions;

		/* step-1: set the full path the meterial to verify signature, the directory specified by caller and the filename is fixed value */
		CHAR cacert_file_path[EPIDA_FILE_PATH_MAX] = { 0 };

		CHAR pubkey_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
		CHAR basename_list_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
		CHAR sig_rl_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
		CHAR grp_rl_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
		CHAR priv_rl_file_path[EPIDA_FILE_PATH_MAX] = { 0 };
		CHAR ver_rl_file_path[EPIDA_FILE_PATH_MAX] = { 0 };

		snprintf(cacert_file_path, sizeof(cacert_file_path) - 1, "%s%s%s",
			res_directory_path,
			PATH_SLASH,
			CACERT_FILE_NAME);
		
		snprintf(pubkey_file_path, sizeof(pubkey_file_path) - 1, "%s%s%s",
			res_directory_path,
			PATH_SLASH,
			PUBKEY_FILE_NAME);

		snprintf(basename_list_file_path, sizeof(basename_list_file_path) - 1, "%s%s%s",
			res_directory_path,
			PATH_SLASH,
			BASENAME_LIST_FILE_NAME);

		snprintf(grp_rl_file_path, sizeof(grp_rl_file_path) - 1, "%s%s%s",
			res_directory_path,
			PATH_SLASH,
			GRP_RL_FILE_NAME);
	    
		snprintf(priv_rl_file_path, sizeof(priv_rl_file_path) - 1, "%s%s%s",
			res_directory_path,
			PATH_SLASH,
			PRIV_RL_FILE_NAME);
		
		snprintf(sig_rl_file_path, sizeof(sig_rl_file_path) - 1, "%s%s%s",
			res_directory_path,
			PATH_SLASH,
			SIG_RL_FILE_NAME);

		snprintf(ver_rl_file_path, sizeof(ver_rl_file_path) - 1, "%s%s%s",
			res_directory_path,
			PATH_SLASH,
			VER_RL_FILE_NAME);
				
		/* step-2: get the meterial to verify signature */

		// 2.1 Group public key
		pub_key = NewBufferFromFile(pubkey_file_path, &pubkey_size);
		if (!pub_key)
		{
			ret = EPIDA_NO_PUBKEY_FILE;
			break;
		}
		if (0 != ReadLoud(pubkey_file_path, pub_key, pubkey_size))
		{
			ret = EPIDA_READ_FILE_FAIL;
			break;
		}

		if (pubkey_size != sizeof(GroupPubKey))
		{
			// 2.2 CA certificate
			if (0 != ReadLoud(cacert_file_path, &cacert, sizeof(cacert)))
			{
				ret = EPIDA_READ_FILE_FAIL;
				break;
			}
			
			// Detect Intel(R) EPID version
			result = EpidParseFileHeader(pub_key, pubkey_size, &epid_version, NULL);
			if ((kEpidNoErr != result) || (kNumEpidVersions <= epid_version))
			{
				ret = EPIDA_INVALID_PUBKEY;
				break;
			}

			// 2.3 GrpRl
			if (FileExists(grp_rl_file_path))
			{
				signed_grp_rl = NewBufferFromFile(grp_rl_file_path, &signed_grp_rl_size);
				if (NULL == signed_grp_rl)
				{
					ret = EPIDA_READ_FILE_FAIL;
					break;
				}
			}

			// 2.4 PrivRl
			if (FileExists(priv_rl_file_path))
			{
				signed_priv_rl = NewBufferFromFile(priv_rl_file_path, &signed_priv_rl_size);
				if (NULL == signed_priv_rl)
				{
					ret = EPIDA_READ_FILE_FAIL;
					break;
				}
			}

			// 2.5 SigRl
			if (FileExists(sig_rl_file_path))
			{
				signed_sig_rl = NewBufferFromFile(sig_rl_file_path, &signed_sig_rl_size);
				if (NULL == signed_sig_rl)
				{
					ret = EPIDA_READ_FILE_FAIL;
					break;
				}
			}

			if (FileExists(ver_rl_file_path))
			{
				ver_rl = NewBufferFromFile(ver_rl_file_path, &ver_rl_size);
				if (NULL == ver_rl)
				{
					ret = EPIDA_READ_FILE_FAIL;
					break;
				}
			}
		}
		
		// Load Verifier pre-computed settings
#if 0
		if (vprecmpi_file->count > 0) {
			vprecmpi_file_size = GetFileSize_S(vprecmpi_file->filename[0], SIZE_MAX);
			verifier_precmp = AllocBuffer(vprecmpi_file_size);

			if (0 != ReadLoud(vprecmpi_file->filename[0], verifier_precmp,
							vprecmpi_file_size)) {
			ret_value = EXIT_FAILURE;
			break;
			}
		}

		if ((NULL != verifier_precomp) && (vprecomp_file_size != sizeof(VerifierPrecomp)))
		{
			ret = EPIDA_ERR;
			break;
		}
#endif

		sig = NewBufferFromFile(sig_file_fullname, &sig_size);
		if (NULL == sig)
		{
			ret = EPIDA_NO_SIG_FILE;
			break;
		}

		msg = NewBufferFromFile(msg_file_fullname, &msg_size);
		if (NULL == msg)
		{
			ret = EPIDA_NO_MSG_FILE;
			break;
		}
		
		//step-4: verify signature
		verify_info.cacert = &cacert;
		verify_info.signed_pub_key = pub_key;
		verify_info.signed_pub_key_size = pubkey_size;
		verify_info.basename_list_file_fullname = basename_list_file_path;
		verify_info.basename = basename;
		verify_info.basename_size = strlen(basename);	

		verify_info.signed_priv_rl = signed_priv_rl;
		verify_info.signed_priv_rl_size = signed_priv_rl_size;
		verify_info.signed_sig_rl = signed_sig_rl;
		verify_info.signed_sig_rl_size = signed_sig_rl_size;
		verify_info.signed_grp_rl = signed_grp_rl;
		verify_info.signed_grp_rl_size = signed_grp_rl_size;
		verify_info.ver_rl = ver_rl;
		verify_info.ver_rl_size = ver_rl_size;

		verify_info.verifier_precomp = &verifier_precomp;
		verify_info.verifier_precomp_size = &vprecomp_file_size;
		ret = Verify(&verify_info, (const EpidSignature*)sig, sig_size, msg, msg_size);		
		if (EPIDA_OK != ret)
		{
			break;
		}
		

		// Store Verifier pre-computed settings
#if 0
		if (vprecmpo_file->count > 0) {
			if (0 != WriteLoud(verifier_precmp, vprecmpi_file_size,
								vprecmpo_file->filename[0])) {
			ret_value = EXIT_FAILURE;
			break;
			}
		}
#endif

		// Success
		ret = EPIDA_OK;
	} while (0);

	// step-4: Free allocated buffers
	EPIDA_SAFE_FREE(pub_key);
	EPIDA_SAFE_FREE(signed_grp_rl);
	EPIDA_SAFE_FREE(signed_priv_rl);
	EPIDA_SAFE_FREE(signed_sig_rl);
	EPIDA_SAFE_FREE(ver_rl);
	EPIDA_SAFE_FREE(verifier_precomp);
	EPIDA_SAFE_FREE(sig);
	EPIDA_SAFE_FREE(msg);

	return ret;
}

#if 0
int main(int argc, char* argv[])
{

	if (EPIDA_OK != verify_sig("D:\\CODE\\EPIDA\\epid_prebuilt_files", "D:\\CODE\\EPIDA\\epid_prebuilt_files\\trans_sig.dat", "D:\\CODE\\EPIDA\\epid_prebuilt_files\\transaction.dat", "1"))
	{
		printf("failed to verify the signature!\r\n");
		return 1;
	}

	printf("succeeded in verifying the signature.\r\n");

	return 0;
}
#endif
