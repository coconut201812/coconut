/* Notice: This part code is out of the coconut's core function. It is supplied as a demo. 
 * So it should not be used in production environment. */
package coconut.epidasdk;

public class Verifier {
	static {
		String resourcePath = Verifier.class.getClassLoader().getResource("libverifysig.so").getPath(); 
	    System.load(resourcePath);
	}

	public native int VerifySig(String res_directory_path, String sig_file_fullname, String msg_file_fullname, String basename);

	public int VerifySignature(String res_directory_path, String sig_file_fullname, String msg_file_fullname, String basename) {
		return VerifySig(res_directory_path, sig_file_fullname, msg_file_fullname, basename);
	}
}
