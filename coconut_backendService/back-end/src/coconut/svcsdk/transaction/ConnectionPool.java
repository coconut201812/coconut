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
package coconut.svcsdk.transaction;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.ibatis.io.Resources;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/* Https connection pool */
public class ConnectionPool {
	private Logger logger = LogManager.getLogger(ConnectionPool.class);
	private PoolingHttpClientConnectionManager connectManager = null;
	private CloseableHttpClient client = null;
	private IdleConnectionMonitorThread monitor = null;
	private HttpClientContext clientCtx = null;
	
	/* singleton pattern */
	private static ConnectionPool instance = null;
	private ConnectionPool() {};
	public static synchronized ConnectionPool getInstance() {
		if (null == instance) {
			// lock only when instance is null
			synchronized(ConnectionPool.class){
				if (null == instance) {
					instance = new ConnectionPool();
				}
			}
		}
		return instance;
	}
	
	/* Initialize connection pool. */
	public void init() throws Exception {
		// server key store
		String serverKeyStore = null;
		String serverKsPsword = null;
		String serverKsType = null;
		
		// trust key store
		String trustKeyStore = null;
		String trustKsPsword = null;
		String trustKsType = null;
		
		// read ssl keystore properties from file
		Properties properties = new Properties();
		InputStream sslCertInput = Resources.getResourceAsStream("sslCertification.properties");
		try {
			properties.load(sslCertInput);
			serverKeyStore = properties.getProperty("serverKeyStore");
			serverKsPsword = properties.getProperty("serverKeyStorePass");
			serverKsType = properties.getProperty("serverKeyStoreType");
			trustKeyStore = properties.getProperty("trustKeyStore");
			trustKsPsword = properties.getProperty("trustKeyStorePass");
			trustKsType = properties.getProperty("trustKeyStoreType");
		} catch (Exception e) {
			throw e;
		} finally {
			sslCertInput.close();
		}
		
        // configure server key store factory
        KeyStore serverKs = KeyStore.getInstance(serverKsType);  
        FileInputStream serverKSStream = new FileInputStream(serverKeyStore);
        try {
        	serverKs.load(serverKSStream, serverKsPsword.toCharArray());  
        } catch (Exception e) {
        	throw e;
        } finally {
        	serverKSStream.close();
        }
        KeyManagerFactory serverKf = KeyManagerFactory.getInstance("SunX509"); 
        serverKf.init(serverKs, serverKsPsword.toCharArray());  
        
        // configure trust key store factory
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
        
        // initialize SSLContext
        SSLContext context = SSLContext.getInstance("TLSv1.2");  
        context.init(serverKf.getKeyManagers(), trustKf.getTrustManagers(), null);  
        
        // initialize connection pool
		LayeredConnectionSocketFactory sslSockFactory = new SSLConnectionSocketFactory(context);
		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
                .register("https", sslSockFactory)
                .build();
		connectManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
		connectManager.setMaxTotal(1000000);
		connectManager.setDefaultMaxPerRoute(1000000);
		clientCtx = HttpClientContext.create();
		HttpClientBuilder clientBuilder = HttpClientBuilder.create().setConnectionManager(connectManager);
		client = clientBuilder.build();
		
		monitor = new IdleConnectionMonitorThread(connectManager);
		monitor.start();
		return;
	}
	
	/* Send content to the pointed url */
	public ImmutablePair<Integer, String> httpPost(String url, String content) {
		int responseStatus = -1;
		String verifierResponse = null;
		HttpPost httpPost = new HttpPost(url);
		int timeOut = 3000;
		RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(timeOut)
                .setConnectTimeout(timeOut).setSocketTimeout(timeOut).build();
		httpPost.setConfig(requestConfig);

		StringEntity reqEntity = new StringEntity(content,"utf-8");
		reqEntity.setContentType("application/json");
		httpPost.setEntity(reqEntity);
		
		HttpEntity respEntity = null;
		try {
			CloseableHttpResponse response = client.execute(httpPost, clientCtx);
			responseStatus = response.getStatusLine().getStatusCode();
			respEntity = response.getEntity();
			InputStream verifierRespStream = respEntity.getContent();
			try {
				verifierResponse = new String(verifierRespStream.readAllBytes());
			} catch (IOException e) {
				logger.warn("verifier response exception.", e);
			} finally {
				verifierRespStream.close();
			}
		} catch (Exception e) {
			logger.warn("TX exception:", e);
		} finally {
			if(respEntity != null) {
				try {
					EntityUtils.consume(respEntity);
				} catch (IOException e) {
					logger.error("TX exception:", e);
				}
			}
		}
		
		return new ImmutablePair<Integer, String>(responseStatus, verifierResponse);
    }
	
	/* recycling */
	public void destroy() {
		// close IdleConnectionMonitorThread
		if (null != monitor) {
			monitor.interrupt();
			try {
				monitor.join(10000);
				logger.info("HTTPS POOL monitor thread close.");
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				if (!monitor.isAlive()) {
					logger.info("HTTPS POOL monitor thread close.");
				}
				logger.info("HTTPS POOL monitor thread close fail.");
			}
		} else {
			logger.warn("HTTPS POOL monitor thread close monitor is null.");
		}
		
		// close CloseableHttpClient
		if (null != client) {
			try {
				client.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				logger.error("CloseableHttpClient close error.", e);
			}
		} else {
			logger.warn("CloseableHttpClient close client is null.");
		}
		
		// close PoolingHttpClientConnectionManager
		if (null != connectManager) {
			connectManager.close();
			logger.info("HTTPS POOL connect manager close.");
		} else {
			logger.warn("HTTPS POOL connect manager close connectManager is null.");
		}
		
		return;
	}
	
}

/* Monitoring of idle connection and invalid connection */
class IdleConnectionMonitorThread extends Thread {
	public Logger logger = LogManager.getLogger(IdleConnectionMonitorThread.class);
    private final PoolingHttpClientConnectionManager connMgr;

    public IdleConnectionMonitorThread(PoolingHttpClientConnectionManager connMgr) {
        super();
        this.connMgr = connMgr;
    }

    @Override
    public void run() {
    	logger.info("THREAD IdleConnectionMonitorThread START!");
        try {
            while (true) {
            	Thread.sleep(5000);
                connMgr.closeExpiredConnections();
            }
        } catch (InterruptedException ex) {
            // terminate
        	logger.info("THREAD IdleConnectionMonitorThread recieved an interrupt!", ex);
        }
        logger.info("THREAD IdleConnectionMonitorThread END!");
        return;
    }
    
}