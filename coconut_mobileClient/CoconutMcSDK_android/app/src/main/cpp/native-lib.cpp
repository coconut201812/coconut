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
 * \CoconutSDK JNI interfaces for android
 */


#include <jni.h>
#include "include/epida_sigmsg_api.h"


extern "C" JNIEXPORT jint
        JNICALL
Java_coconut_mcsdk_Signer_GenerateJoinReq(JNIEnv *env,
                                            jobject /* this */,
                                            jstring res_directory_path,
                                            jstring nonce_file_fullname,
                                            jstring passphrase,
                                            int passphrase_len,
                                            jstring joinreq_file_fullname)
{
    jint ret = -1;
    const char *res_directory_path_cstr = env->GetStringUTFChars(res_directory_path, JNI_FALSE);
    const char *nonce_file_fullname_cstr = env->GetStringUTFChars(nonce_file_fullname, JNI_FALSE);
    const char *passphrase_cstr = env->GetStringUTFChars(passphrase, JNI_FALSE);
    int passphrase_len_c = (int)passphrase_len;
    const char *joinreq_file_fullname_cstr = env->GetStringUTFChars(joinreq_file_fullname, JNI_FALSE);

    if ( (!res_directory_path_cstr) || (!nonce_file_fullname_cstr)
            || (!passphrase_cstr) || (!joinreq_file_fullname_cstr) )
    {
        ret = -1;
    }
    else
    {
        ret = epida_make_join_req(res_directory_path_cstr, nonce_file_fullname_cstr, passphrase_cstr,
                                  passphrase_len_c, joinreq_file_fullname_cstr);
    }

    env->ReleaseStringUTFChars(res_directory_path, res_directory_path_cstr);
    env->ReleaseStringUTFChars(nonce_file_fullname, nonce_file_fullname_cstr);
    env->ReleaseStringUTFChars(passphrase, passphrase_cstr);
    env->ReleaseStringUTFChars(joinreq_file_fullname, joinreq_file_fullname_cstr);

    return ret;
}

extern "C" JNIEXPORT jint
JNICALL
Java_coconut_mcsdk_Signer_GeneratePrvkey(JNIEnv *env,
                                            jobject /* this */,
                                            jstring res_directory_path,
                                            jstring credential_file_fullname,
                                            jstring passphrase,
                                            jint passphrase_len)
{
    jint ret = -1;
    const char *res_directory_path_cstr = env->GetStringUTFChars(res_directory_path, JNI_FALSE);
    const char *credential_file_fullname_cstr = env->GetStringUTFChars(credential_file_fullname, JNI_FALSE);
    const char *passphrase_cstr = env->GetStringUTFChars(passphrase, JNI_FALSE);
    int passphrase_len_c = (int)passphrase_len;

    if ( (!res_directory_path_cstr) || (!credential_file_fullname_cstr) || (!passphrase_cstr) )
    {
        ret = -1;
    }
    else
    {
        ret = epida_generate_prvkey(res_directory_path_cstr, credential_file_fullname_cstr, passphrase_cstr, passphrase_len_c);
    }

    env->ReleaseStringUTFChars(res_directory_path, res_directory_path_cstr);
    env->ReleaseStringUTFChars(credential_file_fullname, credential_file_fullname_cstr);
    env->ReleaseStringUTFChars(passphrase, passphrase_cstr);

    return ret;
}

extern "C" JNIEXPORT jint
JNICALL
Java_coconut_mcsdk_Signer_MakeAllSigs(
         JNIEnv *env,
         jobject /* this */,
         jstring res_directory_path,
         jstring passphrase,
         jint passphrase_len,
         jstring all_sigs_file_fullname)
{
    jint ret = -1;
    const char *res_dir_path_cstr = env->GetStringUTFChars(res_directory_path, JNI_FALSE);
    const char *all_sigs_full_name_cstr = env->GetStringUTFChars(all_sigs_file_fullname, JNI_FALSE);
    const char *passphrase_cstr = env->GetStringUTFChars(passphrase, JNI_FALSE);
    int passphrase_len_c = (int)passphrase_len;

    if ( (!res_dir_path_cstr) || (!passphrase_cstr) || (!all_sigs_full_name_cstr) )
    {
        ret = -1;
    }
    else
    {
        ret = epida_make_sign_file(res_dir_path_cstr, passphrase_cstr, passphrase_len_c, all_sigs_full_name_cstr);
    }

    env->ReleaseStringUTFChars(res_directory_path, res_dir_path_cstr);
    env->ReleaseStringUTFChars(passphrase, passphrase_cstr);
    env->ReleaseStringUTFChars(all_sigs_file_fullname, all_sigs_full_name_cstr);
    return ret;
}

extern "C" JNIEXPORT jint
JNICALL
Java_coconut_mcsdk_Signer_SignTransaction(
        JNIEnv *env,
        jobject /* this */,
        jstring res_directory_path,
        jstring passphrase,
        jint passphrase_len,
        jstring transaction_file_fullname,
        jstring signature_file_fullname)
{
    jint ret = -1;
    const char *res_dir_path_cstr = env->GetStringUTFChars(res_directory_path, JNI_FALSE);
    const char *passphrase_cstr = env->GetStringUTFChars(passphrase, JNI_FALSE);
    int passphrase_len_c = (int)passphrase_len;
    const char *trans_full_name_cstr = env->GetStringUTFChars(transaction_file_fullname, JNI_FALSE);
    const char *sig_fullname_cstr = env->GetStringUTFChars(signature_file_fullname, JNI_FALSE);

    if ( (!res_dir_path_cstr) || (!passphrase_cstr) || (!trans_full_name_cstr) || (!sig_fullname_cstr) )
    {
        ret = -1;
    }
    else
    {
        ret = epida_sign_transaction(res_dir_path_cstr, passphrase_cstr, passphrase_len_c,
                                     trans_full_name_cstr, sig_fullname_cstr);
    }

    env->ReleaseStringUTFChars(res_directory_path, res_dir_path_cstr);
    env->ReleaseStringUTFChars(passphrase, passphrase_cstr);
    env->ReleaseStringUTFChars(transaction_file_fullname, trans_full_name_cstr);
    env->ReleaseStringUTFChars(signature_file_fullname, sig_fullname_cstr);

    return ret;
}

/* generate a member key locally */
extern "C" JNIEXPORT jint
JNICALL
Java_coconut_mcsdk_Signer_LoadPrebuiltFiles(JNIEnv *env,
                                            jobject /* this */,
                                            jstring res_directory_path)
{
    jint ret = -1;
    const char *res_directory_path_cstr = env->GetStringUTFChars(res_directory_path, JNI_FALSE);
    if (!res_directory_path_cstr)
    {
        ret = -1;
    }
    else
    {
        ret = load_epid_prebuilt_files(res_directory_path_cstr);
    }

    env->ReleaseStringUTFChars(res_directory_path, res_directory_path_cstr);

    return ret;
}
