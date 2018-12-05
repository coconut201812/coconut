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

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;

import coconut.svcsdk.kyc.KYCController.E_KYC;

public class Utils {
	private static Logger logger = LogManager.getLogger(Utils.class);
	
	/* Notice: This part code is out of the coconut's core function. So it is supplied as a stub. 
	 * If you want to use coconut in production environment, please implement this function. */
	/* Check login status. Returns user id when session is valid, or returns -1. */
	public static int parseLoginUserId(HttpServletRequest request) {
		return 1;
	}
	
	/* Parse request body to json format */
	public static JSONObject parseRequestToJson(HttpServletRequest request) throws IOException {
		JSONObject clientJson = null;
		if (null != request) {
			InputStream reqIn = request.getInputStream();
			try {
				String content = new String(reqIn.readAllBytes());
				clientJson = new JSONObject(content);
			} catch (IOException e) {
				// throw the exception to the uniform exception handling.
				throw e;
			} catch (JSONException e) {
				logger.trace("Json parse exception:", e);
			} finally {
				reqIn.close();
			}
		}
		return clientJson;
	}
	
	/* Get user id and kyc name from cient's request
	 * input parameters:
	 * 		HttpServletRequest request			servlet request
	 * return:
	 * 		left(JSONObject)					result information returned to client
	 * 		right(ClientParsedData)				parsed data of client's request
	*/
	public static ImmutablePair<JSONObject, ClientParsedData> parseUserIdAndKycFromReq(HttpServletRequest request) throws IOException {
		ClientParsedData clientparsedData = null;
		JSONObject resultJson = null;
		
		int userId = Utils.parseLoginUserId(request);
		if (-1 != userId) {
			clientparsedData = new ClientParsedData();
			clientparsedData.setUser_id(userId);
			
			JSONObject clientJson = Utils.parseRequestToJson(request);
			if (null == clientJson) {
				resultJson = new JSONObject();
				resultJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
				resultJson.put("description", "Request parameter is not correct.");
			} else if (!clientJson.has("kyc")) {
				resultJson = new JSONObject();
				resultJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
				resultJson.put("description", "Request parameter is not correct.");
			} else {
				try {
					E_KYC kyc = E_KYC.valueOf(clientJson.getString("kyc").trim().toUpperCase());
					clientparsedData.setKyc(kyc);
					clientparsedData.setClientReq(clientJson);
				} catch (IllegalArgumentException e) {
					resultJson = new JSONObject();
					resultJson.put("errorCode", ErrorCode.ERROR_REQUEST_NONEXISTENT_KYC.toString());
					resultJson.put("description", "No such kyc.");
				}
			}
		} else {
			resultJson = new JSONObject();
			resultJson.put("errorCode", ErrorCode.ERROR_SESSION_INVALID.toString());
			resultJson.put("description", "Session is invalid.");
		}
		
		return new ImmutablePair<JSONObject, ClientParsedData>(resultJson, clientparsedData);
	}
	
	/* Transform byte array into base64 encoding string */
	public static String base64Encode(byte[] textByte) {
		String encodedText = null;
		if (null != textByte) {
			Base64.Encoder b64Encoder = Base64.getEncoder();
			encodedText = b64Encoder.encodeToString(textByte);
		}
		return encodedText;
	}
	
	/* Transform base64 encoding string into byte array */
	public static byte[] base64Decode(String text) {
		byte[] textByte = null;
		if (null != text) {
			if (0 == (text.length()%4) ) {
				Base64.Decoder b64Decoder = Base64.getDecoder();
				try {
					textByte = b64Decoder.decode(text);
				} catch (IllegalArgumentException e) {
					logger.trace("base64 decode:", e);
				}
			}
		}
		
		return textByte;
	}
	
	/* Get current timestamp in format "yyyy-MM-dd HH:mm:ss" */
	public static String getCurrentTime() {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		Date localDate = new Date();
		
		return dateFormat.format(localDate);
	}
	
	/* Get the time interval between timestamp inputted and current(unit:hours) */
	public static int getTimeIntervalHours(String before) {
		return  getTimeIntervalSeconds(before) / 3600;
	}
	
	/* Get the time interval between timestamp inputted and current(unit:minutes) */
	public static int getTimeIntervalMinutes(String before) {
		return getTimeIntervalSeconds(before) / 60;
	}
	
	/* Get the time interval between timestamp inputted and current(unit:seconds) */
	public static int getTimeIntervalSeconds(String before) {
		int secondsInterval = 0;
		if (null != before) {
			try {
				SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
				dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
				Date txDate = dateFormat.parse(before);
				Date localDate = new Date();
				secondsInterval = (int) ((localDate.getTime() - txDate.getTime()) / 1000);
			} catch (ParseException e) {
				logger.error("getTimeIntervalSeconds:", e);
			}
		} else {
			logger.error("getTimeIntervalSeconds input parameter is null.");
		}
		
		return secondsInterval;
	}
	
}
