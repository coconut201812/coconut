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
 * \brief CoconutMcSDK interfaces for ios swift.
 */


import UIKit

open class Signer: NSObject {
    
    open class func GenerateJoinReq(res_directory_path:String,
                               nonce_file_fullname:String,
                               passphrase:String,
                               passphrase_len:Int32,
                               joinreq_file_fullname:String)->Int32
    {
        let ns_res_directory_path = res_directory_path as NSString
        let c_res_directory_path = ns_res_directory_path.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_nonce_file_fullname = nonce_file_fullname as NSString
        let c_nonce_file_fullname = ns_nonce_file_fullname.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_passphrase = passphrase as NSString
        let c_passphrase = ns_passphrase.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_joinreq_file_fullname = joinreq_file_fullname as NSString
        let c_joinreq_file_fullname = ns_joinreq_file_fullname.cString(using: String.Encoding.utf8.rawValue)
        
        return epida_make_join_req(c_res_directory_path, c_nonce_file_fullname,
                           c_passphrase, passphrase_len, c_joinreq_file_fullname);
    }
   
    open class func GeneratePrvKey(res_directory_path:String,
                                   credential_file_fullname:String,
                                   passphrase:String,
                                   passphrase_len:Int32)->Int32
    {
        let ns_res_directory_path = res_directory_path as NSString
        let c_res_directory_path = ns_res_directory_path.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_credential_file_fullname = credential_file_fullname as NSString
        let c_credential_file_fullname = ns_credential_file_fullname.cString(using: String.Encoding.utf8.rawValue)
   
        let ns_passphrase = passphrase as NSString
        let c_passphrase = ns_passphrase.cString(using: String.Encoding.utf8.rawValue)
        
        return epida_generate_prvkey(c_res_directory_path, c_credential_file_fullname, c_passphrase, passphrase_len)
    }
    
    open class func MakeAllSigs(res_directory_path:String,
                                passphrase:String,
                                passphrase_len:Int32,
                                all_sigs_file_fullname:String)->Int32
    {
        
        let ns_res_directory_path = res_directory_path as NSString
        let c_directory_path = ns_res_directory_path.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_passphrase = passphrase as NSString
        let c_passphrase = ns_passphrase.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_sigs_fullname = all_sigs_file_fullname as NSString
        let c_sigs_fullname = ns_sigs_fullname.cString(using: String.Encoding.utf8.rawValue)
        
        return epida_make_sign_file(c_directory_path, c_passphrase, passphrase_len, c_sigs_fullname)
    }
    
    open class func SignTransaction(res_directory_path:String,
                                    passphrase:String,
                                    passphrase_len:Int32,
                                    transaction_file_fullname:String,
                                    signature_file_fullname:String)->Int32
    {
        let ns_res_directory_path = res_directory_path as NSString
        let c_directory_path = ns_res_directory_path.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_passphrase = passphrase as NSString
        let c_passphrase = ns_passphrase.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_transaction_fullname = transaction_file_fullname as NSString
        let c_transaction_fullname = ns_transaction_fullname.cString(using: String.Encoding.utf8.rawValue)
        
        let ns_signature_fullname = signature_file_fullname as NSString
        let c_signature_fullname = ns_signature_fullname.cString(using: String.Encoding.utf8.rawValue)
        
        return epida_sign_transaction(c_directory_path, c_passphrase, passphrase_len,
                                      c_transaction_fullname, c_signature_fullname)
    }
    
    open class func LoadPrebuiltFiles(res_directory_path:String)->Int32
    {
        let ns_res_directory_path = res_directory_path as NSString
        let c_res_directory_path = ns_res_directory_path.cString(using: String.Encoding.utf8.rawValue)
        
        return load_epid_prebuilt_files(c_res_directory_path)
    }
}
