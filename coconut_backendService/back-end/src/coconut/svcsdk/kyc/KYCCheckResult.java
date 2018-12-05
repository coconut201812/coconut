/* Notice: This part code is out of the coconut's core function. So it is supplied as a stub. 
 * If you want to use coconut in production environment, please implement this module. */
package coconut.svcsdk.kyc;

/* Result of KYC's identity authentication */
public class KYCCheckResult {
	public AuthStatus authStatus;
	public String rejectReason;
	
	public KYCCheckResult() {
		authStatus = AuthStatus.INIT;
		rejectReason = null;
	}
	
	/* authentication status */
	public enum AuthStatus {
		INIT,
		PENDING, 
		FAIL, 
		SUCCESS, 
		UPDATE_FAIL 
	}
}
