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
 * \CoconutSDK JAVA interfaces for android
 */

package coconut.mcsdk;

public class Signer
{
    boolean java_gen_joinreq(String res_directory_path, String nonce_file_fullname,
                           String passphrase, int passphrase_len, String joinreq_file_fullname)
    {
        if (0 == GenerateJoinReq(res_directory_path, nonce_file_fullname,
                            passphrase, passphrase_len, joinreq_file_fullname))
        {
            return true;
        }

        return false;
    }

    boolean java_generate_prvkey(String res_directory_path, String credential_file_fullname,
                                 String passphrase, int passphrase_len)
    {
        if (0 == GeneratePrvkey(res_directory_path, credential_file_fullname, passphrase, passphrase_len))
        {
            return true;
        }

        return false;
    }

    boolean java_make_all_sigs(String res_directory_path, String passphrase, int passphrase_len,
                   String all_sigs_file_fullname)
    {
        if (0 == MakeAllSigs(res_directory_path, passphrase, passphrase_len, all_sigs_file_fullname))
        {
            return true;
        }

        return false;
    }

    boolean java_sign_transaction(String res_directory_path, String passphrase, int passphrase_len,
                    String transcation_file_fullname, String signature_file_fullname)
    {
        if (0 == SignTransaction(res_directory_path, passphrase, passphrase_len,
                    transcation_file_fullname, signature_file_fullname))
        {
            return true;
        }

        return false;
    }

    boolean java_load_prebuilt_files(String res_directory_path)
    {
        if (0 == LoadPrebuiltFiles(res_directory_path))
        {
            return true;
        }

        return false;
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     * */
    public native int GenerateJoinReq(String res_directory_path, String nonce_file_fullname,
                  String passphrase, int passphrase_len, String joinreq_file_fullname);

    /* generate a member key locally */
    public native int GeneratePrvkey(String res_directory_path, String credential_file_fullname,
                  String passphrase, int passphrase_len);

    /* make all signatures by basename list one by one */
    public native int MakeAllSigs(String res_directory_path, String passphrase, int passphrase_len,
                  String all_sigs_file_fullname);

    /* sign a transaction */
    public native int SignTransaction(String res_directory_path, String passphrase, int passphrase_len,
                  String transaction_file_fullname, String signature_file_fullname);

    /* test interface for loading epid prebuilt files */
    public native int LoadPrebuiltFiles(String res_directory_path);
}

