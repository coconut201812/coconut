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

import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import coconut.svcsdk.common.ErrorCode;
import coconut.svcsdk.common.Utils;
import coconut.svcsdk.epid.EPIDService;
import coconut.svcsdk.mapper.BKData;
import coconut.svcsdk.mapper.BKMapper;
import coconut.svcsdk.mapper.BusinessMapper;
import coconut.svcsdk.mapper.EpidData;
import coconut.svcsdk.mapper.EpidMapper;

@Controller
public class TxtTransmitController {
	private Logger logger = LogManager.getLogger(TxtTransmitController.class);
	
	@Autowired
	private SqlSessionTemplate sqlSession;
	
	/* Transaction transmit */
	private JSONObject transactionTransmit(String verifierAddr, JSONObject tx) {
		JSONObject responseJson = null;
		ImmutablePair<Integer, String> verifierResp = ConnectionPool.getInstance().httpPost(verifierAddr, tx.toString());
		if (200 == verifierResp.getLeft()) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SUCCESS.toString());
			responseJson.put("description", "Transaction send successfully.");
			
			String verifierRespContent = verifierResp.getRight();
			if (null != verifierRespContent) {
				if (!verifierRespContent.isEmpty()) {
					responseJson.put("verifierResponse", verifierRespContent);
				}
			}
		} else {
			logger.warn("Transaction send.code:" + verifierResp.getLeft() + " content:" + verifierResp.getRight() + ".");
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_CONNECTION.toString());
			responseJson.put("description", "Transaction transmit error.");
		}
		
		return responseJson;
	}
	
	/* Get verifier's transaction servlet address from database */
	private String getVerifierAddr(String verifierName) {
		BusinessMapper busMapper = sqlSession.getMapper(BusinessMapper.class);
		return busMapper.selectVerifierAddr(verifierName);
	}
	
	/* Check if BK has been recorded in pointed group */
	private boolean checkBK(String groupIdHex, String bk) {
		boolean checkRslt = false;
		BKMapper bkMapper = sqlSession.getMapper(BKMapper.class);
		BKData bkPara = new BKData();
		bkPara.setGroup_id_hex(groupIdHex);
		String bkMd5 = DigestUtils.md5Hex(bk);
		bkPara.setBk_md5(bkMd5);
		List<BKData> selectRslt = bkMapper.selectBK(bkPara);
		
		// Traverse the selected BKs, check if BK equals.
    	if (0 != selectRslt.size()) {
    		Iterator<BKData> iter = selectRslt.iterator();
    		while (iter.hasNext()) {
    			BKData bkRecord = iter.next();
    			if (bkRecord.getBk().equals(bk)) {
    				checkRslt = true;
    			}
    		}
    	}
    	
    	return checkRslt;
	}
	
	/* Interface: signature transaction transmit request */
	@RequestMapping("/txRequest")
	@ResponseBody
	public String TxRequest(HttpServletRequest request) throws Exception {
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
		
		if (!(clientJson.has("verifier") && clientJson.has("txData"))) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
			responseJson.put("description", "Request parameter is not correct.");
			return responseJson.toString();
		}
		
		String verifier = clientJson.getString("verifier");
		JSONObject tx = null;
		try {
			tx = clientJson.getJSONObject("txData");
		} catch(JSONException e) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
			responseJson.put("description", "Request parameter txData is not a json.");
			return responseJson.toString();
		}
		
		if (!(tx.has("signature") && tx.has("groupId"))) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_WRONG.toString());
			responseJson.put("description", "Request parameter txData is not correct.");
			return responseJson.toString();
		}
		String signature = tx.getString("signature");
		String groupId = tx.getString("groupId");
		
		BKMapper bkMapper = sqlSession.getMapper(BKMapper.class);
		String groupIdHex = bkMapper.selectGroupIdHex(groupId);
		if (null == groupIdHex) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
			responseJson.put("description", "Your pointed group id not exsits.");
			return responseJson.toString();
		}
		
		String bk = EPIDService.parseBKfromSig(signature);
		if (null == bk) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
			responseJson.put("description", "Request parameter txData is not correct.");
			return responseJson.toString();
		}
		
		if(checkBK(groupIdHex, bk)) {
			String verifierAddr = getVerifierAddr(verifier);
			if (null == verifierAddr) {
				responseJson = new JSONObject();
				responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
				responseJson.put("description", "No such verifier.");
				return responseJson.toString();
			}
			
			responseJson = transactionTransmit(verifierAddr, tx);
		} else {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_NO_RECORD_EXIST.toString());
			responseJson.put("description", "BK in your signature is not valid.");
		}
		
		return responseJson.toString();	
	}
	
	/* Get the relationship between verifier and kyc */
	@RequestMapping("/getBusinessInfo")
	@ResponseBody
	public String GetBusinessInfo(HttpServletRequest request) {
		JSONObject responseJson = null;
		EpidMapper epidMapper = sqlSession.getMapper(EpidMapper.class);
		List<EpidData> selectRslt = epidMapper.selectBusiness();
		if (null == selectRslt) {
    		responseJson = new JSONObject();
    		responseJson.put("status", ErrorCode.ERROR_NO_RECORD_EXIST.toString());
    		responseJson.put("description", "No such matched record in database.");
    	} else {
    		responseJson = new JSONObject();
    		responseJson.put("status", ErrorCode.ERROR_SUCCESS.toString());
    		responseJson.put("description", "success.");
			Iterator<EpidData> iter = selectRslt.iterator();
			JSONArray businessArray = new JSONArray();
			while (iter.hasNext()) {
				EpidData data = iter.next();
				JSONObject business = new JSONObject();
				business.put(data.getVerifier(), data.getKyc());
				businessArray.put(business);
			}
			responseJson.put("businesses", businessArray);
    	}
		
		return responseJson.toString();
	}
}
