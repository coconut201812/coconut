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
 * \Message signing interface and common data structure definition.
 */

#ifndef _EPIDA_SIGNMSG_H_
#define _EPIDA_SIGNMSG_H_

#include "epid/common/file_parser.h"
#include "epid/common/stdtypes.h"
#include "epid/member/api.h"
#include "epid/common/bitsupplier.h"
#include "epid/common/types.h"
#ifdef TPM_TSS
#include "epid/member/tpm_member.h"
#elif defined TINY
#include "epid/member/tiny_member.h"
#else
#include "epid/member/software_member.h"
#endif
#include "include/epida_define.h"

// Implementation specific configuration parameters.
typedef struct MemberParams MemberParams;

/* data definition about signing data and signing meterial */
typedef struct tagEpidaSignInfo
{
	VOID const* msg;                     /* signing data: message to be sign by EPID */
	size_t msg_len;                      /* signing data: length of message */
	EpidCaCertificate const* cacert;     /* Issuing CA certificate issued by Intel, need verify when use signed file by cacert */
	UCHAR const* gpubkey;          /* signing meterial: group public key in EPID formatted binary */
	size_t gpubkey_size;           /* signing meterial: length of group public key */
	UCHAR const* mprivkey;               /* signing meterial: member private key in EPID formatted binary */
	size_t mprivkey_size;                /* signing meterial: length of member private key */	
	VOID const* basename;                /* signing meterial: basename used by signing */
	size_t basename_len;                 /* signing meterial: length of basename used by signing */
	UCHAR const* signed_sig_rl;          /* signing meterial: signature revocation list in EPID formatted binary */
	size_t signed_sig_rl_size;           /* signing meterial: length signature recocation list */
	MemberPrecomp* member_precomp;       /* signing meterial: pre-computed value to enhance performance */
	UCHAR is_specified_bsn;              /* signing customized info: if specified basename to sign */
	UINT32 specified_bsn_seq;            /* signing customized info: specified basename sequence */	
}epida_sig_info_t;

/* Check if opaque data blob containing CA certificate is authorized */
bool IsCaCertAuthorizedByRootCa(VOID const* data, size_t size);

/* Create Intel(R) EPID signature of message */
EpidStatus SignMsg(epida_sig_info_t* sig_info, EpidSignature** sig, size_t* sig_len);

#endif  // _EPIDA_SIGNMSG_H_