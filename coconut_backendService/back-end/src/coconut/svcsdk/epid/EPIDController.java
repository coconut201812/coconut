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

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import coconut.svcsdk.common.ClientParsedData;
import coconut.svcsdk.common.Configuration;
import coconut.svcsdk.common.ErrorCode;
import coconut.svcsdk.common.Utils;
import coconut.svcsdk.mapper.EpidData;
import coconut.svcsdk.mapper.EpidMapper;

@Controller
public class EPIDController {
	private Logger logger = LogManager.getLogger(EPIDController.class);
	
	// attribute name of the response of step 1 in session
	public static final String EPID_JOIN_STEP1_RESPONSE_ATTR_NAME = "epidJoinStep1Response";
	
	@Autowired
	private SqlSessionTemplate sqlSession;
	
	@Autowired
	private EPIDService epidService;
	
	/* Interface: The first step of EPID certification request */
	@RequestMapping("/certificationRequestStep1")
	@ResponseBody
	public String EpidCertificationRequestStep1(HttpServletRequest request) throws Exception {
		JSONObject responseJson = null;

		ImmutablePair<JSONObject, ClientParsedData> parseResult = Utils.parseUserIdAndKycFromReq(request);
		responseJson = parseResult.getLeft();
		if (null != responseJson) {
			return responseJson.toString();
		}
		
		ClientParsedData clientParsedData = parseResult.getRight();
		responseJson = epidService.requestQualificationCheck(clientParsedData.getUser_id(), clientParsedData.getKyc());
		if (null != responseJson) {
			return responseJson.toString();
		}
		
		HttpSession session = request.getSession();
		responseJson = epidService.requestEpidCertificationStep1(session, clientParsedData.getKyc());
		
		return responseJson.toString();
	}
	
	/* Interface: The second step of EPID certification request */
	@RequestMapping("/certificationRequestStep2")
	@ResponseBody
	public String EpidCertificationRequestStep2(HttpServletRequest request) throws Exception {
		JSONObject responseJson = null;

		int userId = Utils.parseLoginUserId(request);
		if (-1 == userId) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SESSION_INVALID.toString());
			responseJson.put("description", "Session is invalid.");
			return responseJson.toString();
		}
		
		JSONObject clientJson = Utils.parseRequestToJson(request);
		if (null == clientJson) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
			responseJson.put("description", "Request parameter is not correct.");
			return responseJson.toString();
		}
		
		if (!clientJson.has("joinRequest")) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
			responseJson.put("description", "Request parameter is not correct.");
			return responseJson.toString();
		}
		String joinRequest = clientJson.getString("joinRequest");
		
		HttpSession session = request.getSession();
		byte[] step1Resp = (byte[]) session.getAttribute(EPID_JOIN_STEP1_RESPONSE_ATTR_NAME);
		if (null == step1Resp) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_JOIN_STEP1_ABSENT.toString());
			responseJson.put("description", "You should do join service step1 at first.");
			return responseJson.toString();
		}
		
		responseJson = epidService.requestEpidCertificationStep2(userId, step1Resp, joinRequest);
		if(responseJson.getString("errorCode").equals(ErrorCode.ERROR_SUCCESS.toString())) {
			session.removeAttribute(EPID_JOIN_STEP1_RESPONSE_ATTR_NAME);
		}
		
		return responseJson.toString();
	}
	
	/* Interface: revoke certification */
	@RequestMapping("/userRevoke")
	@ResponseBody
	public String UserRevoke(HttpServletRequest request) throws Exception {
		JSONObject responseJson = null;
		
		ImmutablePair<JSONObject, ClientParsedData> parseResult = Utils.parseUserIdAndKycFromReq(request);
		responseJson = parseResult.getLeft();
		if (null != responseJson) {
			return responseJson.toString();
		}
		
		EpidMapper epidMapper = sqlSession.getMapper(EpidMapper.class);
		EpidData revokePara = new EpidData();
		ClientParsedData clientParsedData = parseResult.getRight();
		revokePara.setUser_id(clientParsedData.getUser_id());
		revokePara.setKyc(clientParsedData.getKyc().toString());
		int affectCount = epidMapper.revokeCer(revokePara);
    	if (1 != affectCount) {
    		responseJson = new JSONObject();
    		responseJson.put("errorCode", ErrorCode.ERROR_NO_RECORD_EXIST.toString());
    		responseJson.put("description", "User do not have an EPID certification in use for kyc " + clientParsedData.getKyc() + ".");
    	} else {
    		responseJson = new JSONObject();
    		responseJson.put("errorCode", ErrorCode.ERROR_SUCCESS.toString());
    		responseJson.put("description", "success.");
    	}
    	
		return responseJson.toString();
	}
	
	/* Interface: get basename */
	@RequestMapping("/getBasename")
	@ResponseBody
	public String GetBasename(HttpServletRequest request) {
		JSONObject responseJson = Configuration.getInstance().getBasenameJson();
		responseJson.put("errorCode", ErrorCode.ERROR_SUCCESS.toString());
		responseJson.put("description", "success.");
		
		return responseJson.toString();
	}
	
	/* Interface: get verifier's public key */
	@RequestMapping("/getVerifierPublicKey")
	@ResponseBody
	public String GetVerifierPublicKey(HttpServletRequest request) throws IOException {
		JSONObject responseJson = null;
		
		JSONObject clientJson = Utils.parseRequestToJson(request);
		if (null == clientJson) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
			responseJson.put("description", "Request parameter is not correct.Content is not a json.");
			return responseJson.toString();
		}
		
		if (!clientJson.has("verifier")) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
			responseJson.put("description", "Request parameter is not correct.Verifier does not exist.");
			return responseJson.toString();
		}
		String verifier = clientJson.getString("verifier");
		
		EpidMapper epidMapper = sqlSession.getMapper(EpidMapper.class);
		List<EpidData> selectRslt = epidMapper.selectVerifierPubKey(verifier);
		if (selectRslt.isEmpty()) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_NO_RECORD_EXIST.toString());
			responseJson.put("description", "No such matched record in database.");
		} else {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SUCCESS.toString());
			responseJson.put("description", "success.");
			JSONObject publicKeysJson = epidService.formatVerifierPubKey(selectRslt);
			responseJson.put("publicKeys", publicKeysJson);
		}
		
		return responseJson.toString();
	}
	
	/* Interface: receive the signatures signed with each basename */
	@RequestMapping("/signAllBasenames")
	@ResponseBody
	public String SignAllBasenames(HttpServletRequest request) throws Exception {
		JSONObject responseJson = null;
		
		ImmutablePair<JSONObject, ClientParsedData> parseResult = Utils.parseUserIdAndKycFromReq(request);
		responseJson = parseResult.getLeft();
		if (null != responseJson) {
			return responseJson.toString();
		}
		
		JSONArray signatures = null;
		ClientParsedData clientParsedData = parseResult.getRight();
		try {
			signatures = clientParsedData.getClientReq().getJSONArray("signatures");
		} catch(JSONException e) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
			responseJson.put("description", "Request parameter signatures is not valid.");
			return responseJson.toString();
		}
		
		JSONArray bks = epidService.parseBKsfromSigArray(signatures);
		if (null == bks) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
			responseJson.put("description", "Request parameter signatures is not valid.");
			return responseJson.toString();
		}
		
		try {
			responseJson = epidService.insertBK(clientParsedData.getUser_id(), clientParsedData.getKyc(), bks, signatures.toString());
		} catch (DuplicateKeyException e) {
			logger.info("Function SignAllBasenames:insert bks failed.", e);
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SERVER_ERROR.toString());
			responseJson.put("description", "Your bk already exists.");
		} catch (Exception e) {
			logger.error("Function SignAllBasenames:insert bks failed.", e);
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SERVER_ERROR.toString());
			responseJson.put("description", "Server inner error.");
		}
		
		return responseJson.toString();
	}
}
