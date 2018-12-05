package coconut.mcsdk;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import java.io.File;
import java.io.*;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("CoconutMcSDK");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        
        /* make all sigs by basename list */
        File filesDir = this.getFilesDir();
        String filesDirPath = filesDir.getAbsolutePath();
        String allSigsPath = filesDir.getAbsolutePath() + "/all_sigs.dat";
        Signer signer = new Signer();

        String info_msg = "";
        String passphrase = "Mypassword";
        if (true == signer.java_load_prebuilt_files(filesDirPath))
        {
            info_msg += "Load prebuilt files successfully!\r\n";
        }
        else
        {
            info_msg += "Fail to load prebuilt files>>>\r\n";
        }

        if (true == signer.java_gen_joinreq(filesDirPath, filesDirPath + "/epid_nonce.dat",
                passphrase, passphrase.length(), filesDirPath + "/joinReq.dat"))
        {
            info_msg += "Generate join request successfully!\r\n";
        }
        else
        {
            info_msg += "Failed to generate join request>>>\r\n";
        }

        if (true == signer.java_generate_prvkey(filesDirPath, filesDirPath + "/epid_credential.dat", passphrase, passphrase.length()))
        {
            info_msg += "Generate member private key successfully!\r\n";
        }
        else
        {
            info_msg += "Failed to generate member private key>>>\r\n";
        }

        boolean ret = signer.java_make_all_sigs(filesDirPath, passphrase, passphrase.length(), allSigsPath);
        if (true == ret)
        {
            info_msg += "Make all signatures successfully!\r\n";
        }
        else
        {
            info_msg += "Failed to make all signatures>>>\r\n";
        }

        String trans_file_fullname = filesDirPath + "/transaction.dat";
        String signature_file_fullname = filesDirPath + "/trans_sig.dat";
        boolean retn = signer.java_sign_transaction(filesDirPath, passphrase, passphrase.length(), trans_file_fullname, signature_file_fullname);
        if (true == retn)
        {
            info_msg += "Sign the transaction successfully!\r\n";
        }
        else
        {
            info_msg += "Failed to sign the transaction>>>\r\n";
        }

        tv.setText(info_msg);
    }
 }
