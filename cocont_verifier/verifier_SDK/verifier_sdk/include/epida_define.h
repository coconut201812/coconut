#ifndef _EPIDA_DEFINE_H_
#define _EPIDA_DEFINE_H_

typedef char CHAR;
typedef unsigned char UCHAR;

typedef char INT8;
typedef unsigned char UINT8;

typedef short INT16;
typedef unsigned short UINT16;

typedef int INT32;
typedef unsigned int UINT32;

typedef long long INT64;
typedef unsigned long long UINT64;

typedef void VOID;

typedef enum enEpidaRetErrCode
{
	EPIDA_ERR = -1,
	EPIDA_OK = 0,
	EPIDA_INVALID_PARAMETERS = 1,
	EPIDA_NO_RES_PATH = 2,
	EPIDA_INVALID_RES_PATH_LEN = 3,
	EPIDA_NO_CACER_FILE = 4,
	EPIDA_INVALID_CACER = 5,
	EPIDA_NO_PUBKEY_FILE = 6,
	EPIDA_INVALID_PUBKEY = 7,
	EPIDA_NO_PRIVKEY_FILE = 8,
	EPIDA_INVALID_PRIVKEY = 9,
	EPIDA_NO_BSN_LIST_FILE = 10,
	EPIDA_INVALID_BSN_LIST = 11,

	EPIDA_SINMSG_FAIL = 12,
	EPIDA_READ_FILE_FAIL = 13,
	EPIDA_WRITE_FILE_FAIL = 14,
	EPIDA_NO_BSN_SIG_FILE_PATH = 15,

	EPIDA_NO_TRANS_FILE_PATH = 16,
	EPIDA_NO_TRANS_FILE = 17,
	EPIDA_NO_TRANSC_SIG_PATH = 18,

	EPIDA_NO_CREDENTIAL_FILE_PATH = 19,
	EPIDA_NO_CREDENTIAL_FILE = 20,
	EPIDA_INVALID_CREDENTIAL = 21,
	EPIDA_NO_MEMBERKEY_FILE_PATH = 22,
	EPIDA_NO_MEMBERKEY_FILE = 23,
	EPIDA_GEN_MEMBERKEY_FAIL = 24,

	EPIDA_NO_SIG_FILE_PATH = 25,
	EPIDA_NO_SIG_FILE = 26,
	EPIDA_NO_MSG_FILE_PATH = 27,
	EPIDA_NO_MSG_FILE = 28,
	EPIDA_NO_VERIFY_BASENAME = 29,
	EPIDA_SET_VERIFIER_BSN_FAIL = 30,
	EPIDA_SET_VERIFIER_CTX_FAIL = 31,
	EPIDA_VERIFY_SIG_FAIL = 32,

	EPIDA_NO_NI_FILE = 33,
	EPIDA_NO_RANDOM_FILE = 34,
	EPIDA_NO_PRIVATEF_FILE = 35,
	EPIDA_INVALID_PRIVATEF = 36,
	EPIDA_NO_JOINREQ_FILE_PATH = 37,
	EPIDA_MAKE_JOINREQ_FAIL = 38,

	EPIDA_NO_PASSPHRASE = 39,
	EPIDA_ENCRYPT_FAIL = 40,
	EPIDA_DECRYPT_FAIL = 41,

}EPIDA_RET_ERR_CODE_E;


#define CACERT_FILE_NAME          "epid_cacert.bin"
#define PRIVATEF_FILE_NAME        "epid_privatef.dat"
#define MPRIVKEY_FILE_NAME        "epid_mprivkey.dat"
#define PUBKEY_FILE_NAME          "epid_pubkey.bin"
#define BASENAME_LIST_FILE_NAME   "epid_basenames.dat"

#define GRP_RL_FILE_NAME          "epid_grprl.bin"
#define PRIV_RL_FILE_NAME         "epid_privrl.bin"
#define SIG_RL_FILE_NAME          "epid_sigrl.bin"
#define VER_RL_FILE_NAME          "epid_verrl.dat"

#define EPIDA_FILE_PATH_MAX       (512)
#define EPIDA_RES_DIR_PATH_MAX    (384)
#define PATH_SLASH                "/"

#define EPIDA_SAFE_FREE(ptr) \
do \
{ \
	if (NULL != (ptr)) \
	{ \
		free(ptr); \
		(ptr) = NULL; \
	} \
}while(0)

#define EPIDA_SAFE_CLEANUP(ptr, mem_size) \
do \
{ \
	if (NULL != (ptr)) \
	{ \
		memset(ptr, 0, mem_size); \
		free(ptr); \
		(ptr) = NULL; \
	} \
}while(0)

#endif