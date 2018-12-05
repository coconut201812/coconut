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
package coconut.svcsdk.common;

import java.io.InputStream;
import java.util.Properties;

import org.apache.ibatis.io.Resources;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;

/* Coconut configuration class */
public class Configuration {
	// log4j
	private Logger logger = LogManager.getLogger(Configuration.class);
	
	// unify configuring source (singleton pattern)
	private static Configuration instance = null;
	private Configuration() {};
	public static Configuration getInstance() {
		if (null == instance) {
			synchronized(Configuration.class){
				if (null == instance) {
					instance = new Configuration();
				}
			}
		}
		return instance;
	}
	
	// configuration content
	private int epidExpirationTime;
	private int epidGroupCapacity;
	private JSONObject basenameJson;
	
	public int getEpidExpirationTime() {
		return epidExpirationTime;
	}

	public int getEpidGroupCapacity() {
		return epidGroupCapacity;
	}

	public JSONObject getBasenameJson() {
		return basenameJson;
	}
	
	// only allowed to be invoked by load-on-startup initialization 
	protected void ConfigInit() throws Exception {
		InputStream basenameIn = Resources.getResourceAsStream("basenames.json");
		try {
			byte[] basenameContent = basenameIn.readAllBytes();
			basenameJson = new JSONObject(new String(basenameContent));
			logger.info("Configuration basenames:" + basenameJson.toString());
		} catch (Exception e) {
			throw e;
		} finally {
			basenameIn.close();
		}
		
		InputStream fEpidIn = Resources.getResourceAsStream("epid.properties");
		try {
			Properties properties = new Properties();
			properties.load(fEpidIn);
			epidGroupCapacity = Integer.parseInt(properties.getProperty("groupCapacity"));
			epidExpirationTime = Integer.parseInt(properties.getProperty("epidExpirationTime"));
			logger.info("Configuration epidGroupCapacity:" + epidGroupCapacity);
			logger.info("Configuration epidExpirationTime:" + epidExpirationTime);
		} catch (Exception e) {
			throw e;
		} finally {
			fEpidIn.close();
		}
		
		return;
	}
}
