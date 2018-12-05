
#include <jni.h>

#ifndef _Included_Verifier
#define _Included_Verifier
#ifdef __cplusplus

extern "C" {
#endif

JNIEXPORT jint JNICALL Java_coconut_epidasdk_Verifier_VerifySig(JNIEnv *env, jclass cls,
	jstring res_directory_path, jstring sig_file_fullname, jstring msg_file_fullname, jstring basename);

#ifdef __cplusplus
}
#endif
#endif
