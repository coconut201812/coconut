/* Notice: This part code is out of the coconut's core function. So it is supplied as a stub. 
 * If you want to use coconut in production environment, please implement this module. */
package coconut.svcsdk.kyc;

import java.io.IOException;

import org.springframework.stereotype.Component;

import coconut.svcsdk.kyc.KYCCheckResult.AuthStatus;

@Component
public class KYCInstance1 {
	
	/* function: fetch the latest authentication status */
	public AuthStatus authStatusUpdateProc(int userId) throws IOException {
		return AuthStatus.SUCCESS;
	}

}