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
 * \brief Bridging header files between Objective-C and swift.
 */

#ifndef CoconutMcSDK_Bridging_Header_h
#define CoconutMcSDK_Bridging_Header_h


/* make join request for applying certificate online */
int epida_make_join_req(const char* res_directory_path, const char* nonce_file_fullname,
                        const char* passphrase, int passphrase_len, const char* joinreq_file_fullname);

/* generate a member key locally */
int epida_generate_prvkey(const char* res_directory_path, const char* credential_file_fullname,
                          const char* passphrase, int passphrase_len);

/* make a specified group signature file including all signatures corresponding to different basename */
int epida_make_sign_file(const char* res_directory_path, const char* passphrase,
                         int passphrase_len, const char* all_sigs_file_fullname);

/* sign a transaction in the specified group */
int epida_sign_transaction(const char* res_directory_path, const char* passphrase, int passphrase_len,
                           const char* transaction_file_fullname, const char* signature_file_fullname);

/* test interface for loading epid prebuilt files */
int load_epid_prebuilt_files(const char* res_directory_path);

#endif /* CoconutEpida_Bridging_Header_h */


