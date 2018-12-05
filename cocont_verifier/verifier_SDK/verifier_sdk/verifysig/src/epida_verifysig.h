
/*!
 * \file
 * \brief Signature verification interface.
 */
#ifndef _EPIDA_VERIFYSIG_H_
#define _EPIDA_VERIFYSIG_H_

#include <stddef.h>
#include "epid/common/errors.h"
#include "epid/common/stdtypes.h"
#include "epid/common/types.h"
#include "include/epida_define.h"


struct EpidCaCertificate;

/* verify info to verify a signature, including verifier meterail and data to be verify */
typedef struct tagVerify_info
{
	EpidCaCertificate const* cacert;      /* meterial to be verified: Issuing CA certification by Intel EPID */
	VOID const* signed_pub_key;           /* meterial to be verified: signed group public key */
	size_t signed_pub_key_size;
	const CHAR* basename_list_file_fullname;
	VOID const* basename;                /* meterial to be verified: basename to be used by verifier */
	size_t basename_size;
	
	VOID const* signed_priv_rl;         /* meterial to be verified: signed member private key revocation list */
	size_t signed_priv_rl_size;
	VOID const* signed_sig_rl;          /* meterial to be verified: signed signature revocation list */
	size_t signed_sig_rl_size;
	VOID const* signed_grp_rl;          /* meterial to be verified: signed group revocation list */
	size_t signed_grp_rl_size;
	VOID const* ver_rl;
	size_t ver_rl_size;

	VOID** verifier_precomp;
	size_t* verifier_precomp_size;
}verify_info_t;

/// Check if opaque data blob containing CA certificate is authorized
bool IsCaCertAuthorizedByRootCa(void const* data, size_t size);

/// verify Intel(R) EPID 2.x signature
EpidStatus Verify(verify_info_t* verify_info,
	EpidSignature const* sig, size_t sig_len,
	void const* msg, size_t msg_len
        /* void const* basename, size_t basename_len,
           void const* signed_priv_rl, size_t signed_priv_rl_size,
           void const* signed_sig_rl, size_t signed_sig_rl_size,
           void const* signed_grp_rl, size_t signed_grp_rl_size,
           VerifierRl const* ver_rl, size_t ver_rl_size,
           void const* signed_pub_key, size_t signed_pub_key_size,
           struct EpidCaCertificate const* cacert, HashAlg hash_alg,
           void** verifier_precomp, size_t* verifier_precomp_size*/);

#endif  // _EPIDA_VERIFYSIG_H_
