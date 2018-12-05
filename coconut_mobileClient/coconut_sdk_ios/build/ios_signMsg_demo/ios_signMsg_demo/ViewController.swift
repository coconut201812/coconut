//
//  ViewController.swift
//  ios_signmsg_demo
//
//  Created by xi yang on 2018/9/3.
//  Copyright © 2018年 xi yang. All rights reserved.
//

import UIKit
import CoconutMcSDK

import Security

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        let DocumentPath = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory,
                FileManager.SearchPathDomainMask.userDomainMask, true)
        print("sandbox:document path:", DocumentPath)
        
        let applicationPath = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.applicationDirectory,
                FileManager.SearchPathDomainMask.userDomainMask, true)
        print("sandbox:application path:", applicationPath)
    }
    
    
    @IBAction func GenJoinReq(_ sender: Any) {
        let DocumentPath = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory,
                                                               FileManager.SearchPathDomainMask.userDomainMask, true)
        
        let ns_nonce_filename = "/epid_nonce.dat"
        let ns_nonce_file_fullname = "\(DocumentPath[0])\(ns_nonce_filename)"
        let ns_joinreq_file_filename = "/epid_joinReq.dat"
        let ns_joinreq_file_fullname = "\(DocumentPath[0])\(ns_joinreq_file_filename)"
        let ns_passphrase = "myPassword"
        
        if (0 == Signer.GenerateJoinReq(res_directory_path: DocumentPath[0], nonce_file_fullname: ns_nonce_file_fullname,
                                   passphrase: ns_passphrase, passphrase_len: 10,
                                   joinreq_file_fullname: ns_joinreq_file_fullname))
        {
            print("Generate join request successfully!")
            makeAllSigsOut.text = "Generate join request successfully!"
        }
        else
        {
            print("Failed to generate join request>>>>")
            makeAllSigsOut.text = "Failed to generate join request>>>"
            makeAllSigsOut.adjustsFontSizeToFitWidth = true;
        }
    }
    
    @IBAction func GenPrvKey(_ sender: Any) {
        let DocumentPath = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory,
            FileManager.SearchPathDomainMask.userDomainMask, true)
        
        let credential_filename = "/epid_credential.dat"
        let credential_fullname = "\(DocumentPath[0])\(credential_filename)"
        let ns_passphrase = "myPassword"
        
        if (0 == Signer.GeneratePrvKey(res_directory_path:DocumentPath[0], credential_file_fullname:credential_fullname,                                        passphrase:ns_passphrase, passphrase_len: 10))
        {
            print("Generate private key successfully!")
            makeAllSigsOut.text = "Generate private key successfully!"
        }
        else
        {
            print("Failed to generate private key>>>>")
            makeAllSigsOut.text = "Failed to generate private key>>>"
            makeAllSigsOut.adjustsFontSizeToFitWidth = true;
        }
    }
    
    
    @IBAction func LoadPreBuiltFiles(_ sender: Any) {
        let DocumentPath = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory,
                                        FileManager.SearchPathDomainMask.userDomainMask, true)
        if (0 == Signer.LoadPrebuiltFiles(res_directory_path: DocumentPath[0]))
        {
            print("Load prebuilt files successfully!")
            makeAllSigsOut.text = "Load prebuilt files successfully!"
        }
        else
        {
            print("Failed to load prebuilt files>>>>")
            makeAllSigsOut.text = "Failed to load prebuilt files>>>"
            makeAllSigsOut.adjustsFontSizeToFitWidth = true;
        }
    }
    
    @IBAction func sigmsg(_ sender: Any) {
        let DocumentPath = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory,
            FileManager.SearchPathDomainMask.userDomainMask, true)
        
        let ns_passphrase = "myPassword"
        let sigs_dat_filename = "/epida_sigs.dat"
        let sigs_fullname = "\(DocumentPath[0])\(sigs_dat_filename)"
        
        if (0 == Signer.MakeAllSigs(res_directory_path: DocumentPath[0], passphrase: ns_passphrase, passphrase_len: 10,
            all_sigs_file_fullname: sigs_fullname))
        {
            print("Make all sigs successfully!")
            makeAllSigsOut.text = "Make all sigs successfully!"
        }
        else
        {
            print("Failed to make all sigs>>>>")
            makeAllSigsOut.text = "Failed to make all sigs>>>"
            makeAllSigsOut.adjustsFontSizeToFitWidth = true;
        }
    }
    
    @IBAction func SignTransaction(_ sender: Any) {
        let documents_path = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory,
                 FileManager.SearchPathDomainMask.userDomainMask, true)
        
        let ns_passphrase = "myPassword"
        let trans_file_name = "/transaction.dat"
        let trans_dat_fullname = "\(documents_path[0])\(trans_file_name)"
        
        let trans_sig_file_name = "/trans_sig.dat"
        let trans_sig_fullname = "\(documents_path[0])\(trans_sig_file_name)"
        
        if (0 == Signer.SignTransaction(res_directory_path: documents_path[0], passphrase: ns_passphrase, passphrase_len: 10, transaction_file_fullname: trans_dat_fullname, signature_file_fullname: trans_sig_fullname))
        {
            print("sign the transaction successfully!")
            makeAllSigsOut.text = "sign the transaction successfully!"
            makeAllSigsOut.isHighlighted = true
        }
        else
        {
            print("Failed to sign the transaction>>>>")
            makeAllSigsOut.text = "Failed to sign the transaction>>>>"
            makeAllSigsOut.isHighlighted = true
        }
    }
   
    @IBOutlet weak var makeAllSigsOut: UILabel!
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}
