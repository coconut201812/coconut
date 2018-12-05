#include "Verifier.h"

#include "include/epida_verifysig_api.h"
#ifdef __cplusplus
extern "C"
{
#endif


///VerifySig(String res_directory_path, String sig_file_fullname, String msg_file_fullname, String basename)

JNIEXPORT jint JNICALL Java_coconut_epidasdk_Verifier_VerifySig(JNIEnv *env, jclass cls, 
	         jstring res_directory_path, jstring sig_file_fullname, jstring msg_file_fullname, jstring basename)
{
        (void)cls;

	jint ret = -1;
	const char *res_dir_path_cstr = (*env)->GetStringUTFChars(env, res_directory_path, JNI_FALSE);
	const char *sig_file_fullname_cstr = (*env)->GetStringUTFChars(env, sig_file_fullname, JNI_FALSE);
	const char *msg_file_fullname_cstr = (*env)->GetStringUTFChars(env, msg_file_fullname, JNI_FALSE);
	const char *basename_cstr = (*env)->GetStringUTFChars(env, basename, JNI_FALSE);
	if ((!res_dir_path_cstr) || (!sig_file_fullname_cstr) || (!msg_file_fullname_cstr) || (!basename_cstr) )
	{
		ret = -1;
	}
	else
	{
		ret = verify_sig(res_dir_path_cstr, sig_file_fullname_cstr, msg_file_fullname_cstr, basename_cstr);
	}

	(*env)->ReleaseStringUTFChars(env, res_directory_path, res_dir_path_cstr);
	(*env)->ReleaseStringUTFChars(env, sig_file_fullname, sig_file_fullname_cstr);
	(*env)->ReleaseStringUTFChars(env, msg_file_fullname, msg_file_fullname_cstr);
	(*env)->ReleaseStringUTFChars(env, basename, basename_cstr);

	return ret;
}

#ifdef __cplusplus
}
#endif
