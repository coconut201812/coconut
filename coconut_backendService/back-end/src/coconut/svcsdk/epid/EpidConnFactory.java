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
package coconut.svcsdk.epid;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyStore;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.ibatis.io.Resources;

/* Https connection factory */
public class EpidConnFactory {
	private SSLSocketFactory sslFactory = null;
	
	/* singleton pattern */
	private static EpidConnFactory instance = null;
	private EpidConnFactory() {};
	public static synchronized EpidConnFactory getInstance() {
		if (null == instance) {
			// Lock only when instance is null
			synchronized(EpidConnFactory.class){
				if (null == instance) {
					instance = new EpidConnFactory();
				}
			}
		}
		return instance;
	}
	
	/* Init connection factory. Invoked when coconut backend starts. */
	public void init() throws Exception {
		String trustKeyStore = null;
		String trustKsPsword = null;
		String trustKsType = null;
		
		// Read ssl keystore properties from file
		Properties properties = new Properties();
		InputStream sslCertInput = Resources.getResourceAsStream("sslCertification.properties");
		try {
			properties.load(sslCertInput);
			trustKeyStore = properties.getProperty("trustKeyStore");
			trustKsPsword = properties.getProperty("trustKeyStorePass");
			trustKsType = properties.getProperty("trustKeyStoreType");
		} catch (Exception e) {
			throw e;
		} finally {
			sslCertInput.close();
		}
        
        // Set trust key store factory
        KeyStore trustKs = KeyStore.getInstance(trustKsType);  
        FileInputStream trustKSStream = new FileInputStream(trustKeyStore);
        try {
        	trustKs.load(trustKSStream, trustKsPsword.toCharArray()); 
        } catch (Exception e) {
        	throw e;
        } finally {
        	trustKSStream.close();
        }
        TrustManagerFactory trustKf = TrustManagerFactory.getInstance("SunX509");
        trustKf.init(trustKs); 
        
        // Init SSLContext
        SSLContext context = SSLContext.getInstance("TLSv1.2");  
        context.init(null, trustKf.getTrustManagers(), null);  
        sslFactory = context.getSocketFactory();
       
		return;
	}
	
	/* Send content to pointed url
	 * input parameters:
	 * 		String url							url
	 * 		String content						content of request
	 * return:
	 * 		left(Integer)						http status in response
	 * 		right(String)						content of response
	*/
	public ImmutablePair<Integer, byte[]> httpPost(String url, byte[] content) throws Exception { 
		int responseStatus = 0;
		byte[] verifierResponse = null;
		
		URL serverUrl = new URL(url);
		HttpsURLConnection httpsConn = (HttpsURLConnection) serverUrl.openConnection();
		try {
			httpsConn.setSSLSocketFactory(sslFactory);
			httpsConn.setRequestMethod("POST");
			httpsConn.setRequestProperty("Content-type", "application/octet-stream");
			httpsConn.setInstanceFollowRedirects(false);
			httpsConn.setDoInput(true);
			httpsConn.setDoOutput(true);
			
			// Set timeout
			int timeOut = 3000;
			httpsConn.setConnectTimeout(timeOut);
			httpsConn.setReadTimeout(timeOut);
			
			// Write request content
			OutputStream outStream = httpsConn.getOutputStream();
			try {
				outStream.write(content);
				outStream.flush();
			} catch (IOException e) {
				throw e;
			} finally {
				outStream.close();
			}
			
			// Connect & Read response
			httpsConn.connect();
			responseStatus = httpsConn.getResponseCode();
			if (200 == responseStatus) {
				InputStream respStream = httpsConn.getInputStream();
				try {
					verifierResponse = respStream.readAllBytes();
				} catch (IOException e) {
					throw e;
				} finally {
					respStream.close();
				}
			}
		} catch (Exception e) {
			throw e;
		} finally {
			httpsConn.disconnect();
		}
		
		return new ImmutablePair<Integer, byte[]>(responseStatus, verifierResponse);
    }
	
}