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
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.ibatis.io.Resources;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import coconut.svcsdk.common.Configuration;
import coconut.svcsdk.common.ErrorCode;
import coconut.svcsdk.common.Utils;
import coconut.svcsdk.kyc.KYCInstance1;
import coconut.svcsdk.kyc.KYCCheckResult.AuthStatus;
import coconut.svcsdk.kyc.KYCController.E_KYC;
import coconut.svcsdk.mapper.BKData;
import coconut.svcsdk.mapper.BKMapper;
import coconut.svcsdk.mapper.EpidData;
import coconut.svcsdk.mapper.EpidMapper;

@Component
public class EPIDService {
	private Logger logger = LogManager.getLogger(EPIDService.class);
	
	@Autowired
	private SqlSessionTemplate sqlSession;

	@Autowired
	private KYCInstance1 kycInstance;
	
	/* Parse BKs from a sort of signatures */
	protected JSONArray parseBKsfromSigArray(JSONArray signatures) {
		JSONArray result = null;
		int basenameCount = Configuration.getInstance().getBasenameJson().getJSONArray("basenames").length();
		if (signatures.length() == basenameCount) {
			result = new JSONArray();
			Iterator<Object> iter = signatures.iterator();
			while (iter.hasNext()) {
				String bk = parseBKfromSig((String)iter.next());
				if (null == bk) {
					result = null;
					break;
				}
				result.put(bk);
			}
		}
		
		return result;
	}
	
	/* Get the time user should wait for requesting certification */
	private int getCertReqTimeRemaining(int userId) {
		int timeRemaining = 0;
		EpidMapper epidMapper = sqlSession.getMapper(EpidMapper.class);
		EpidData selectPara = new EpidData();
		selectPara.setUser_id(userId);
		EpidData data = epidMapper.selectMaxAttemptTimestamp(selectPara);
		if (null != data) {
			int timeIntervalHours = Utils.getTimeIntervalHours(data.getPublish_timestamp());
			timeRemaining = Configuration.getInstance().getEpidExpirationTime() - timeIntervalHours;
		}
		
		return timeRemaining;
	}
	
	/* confirm whether user can request EPID certification or not */
	protected JSONObject requestQualificationCheck(int userId, E_KYC kyc) throws Exception {
		JSONObject responseJson = null;
		
		do {
			// 1、Check identity authentication status.
			if (E_KYC.JUMIO == kyc) {
				AuthStatus authStatus = kycInstance.authStatusUpdateProc(userId);
				if (AuthStatus.PENDING == authStatus) {
					responseJson = new JSONObject();
					responseJson.put("errorCode", ErrorCode.ERROR_NO_RECORD_EXIST.toString());
					responseJson.put("description", "Your authenticaiton is pending. Please wait.");
					break;
				} else if (AuthStatus.UPDATE_FAIL == authStatus) {
					responseJson = new JSONObject();
		    		responseJson.put("errorCode", ErrorCode.ERROR_KYC_CONNECT.toString());
		    		responseJson.put("description", "Update authentication status from KYC failed. Please retry later.");
		    		break;
				} else if (AuthStatus.SUCCESS != authStatus) {
					responseJson = new JSONObject();
					responseJson.put("errorCode", ErrorCode.ERROR_NO_RECORD_EXIST.toString());
					responseJson.put("description", "You do not have a valid authenticaiton.");
					break;
				}
			}

    		// 2、Get time to wait.
    		int timeRemaining = getCertReqTimeRemaining(userId);
    		if (timeRemaining > 0) {
    			responseJson = new JSONObject();
    			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_TOO_OFTEN.toString());
    			responseJson.put("timeToWait", timeRemaining + " hours");
    			responseJson.put("description", "You have requested EPID certification too often"
						+ ".Please retry after " + timeRemaining + "hours.");
				break;
    		}
	    	
	    	// 3、Confirm whether there is a certification in use.
    		EpidMapper epidMapper = sqlSession.getMapper(EpidMapper.class);
    		EpidData selectPara = new EpidData();
    		selectPara.setUser_id(userId);
    		selectPara.setKyc(kyc.toString());
	    	String cer = epidMapper.selectEpidCer(selectPara);
	    	if (null != cer) {
				responseJson = new JSONObject();
				responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
				responseJson.put("description", "An EPID certification is inuse,you should invoke it at first.");
			}
		} while (false);
		
		return responseJson;
	}
	
	/* Get the keyid in authdata1 for EPID join process */
	private byte[] getKeyID() throws IOException {
		byte[] keyId = null;
		InputStream derIn = Resources.getResourceAsStream("IOT_CAK_IssuingCA0_VendID160.der");
		try {
			ASN1InputStream asnIn = new ASN1InputStream(derIn);
			try {
				ASN1Primitive pri = asnIn.readObject();
				DLSequence certSeq = (DLSequence)pri;
				
				// parse cert sequence
				ASN1SequenceParser certSeqParser = certSeq.parser();
				certSeqParser.readObject();																// version
				certSeqParser.readObject();																// privateKeyAlgorithm
				DEROctetString privDerOct = (DEROctetString)(certSeqParser.readObject());				// privateKey
				
				// parse private key sequence
				DLSequence privSeq = (DLSequence) ASN1Primitive.fromByteArray(privDerOct.getOctets());
				ASN1SequenceParser privSeqParser = privSeq.parser();
				privSeqParser.readObject();																// version
				privSeqParser.readObject();																// privateKey
				DERTaggedObject pubKeyTaggedObj = (DERTaggedObject)(privSeqParser.readObject());		// publicKey
				DERBitString pubKey = (DERBitString)pubKeyTaggedObj.getObject();
				
				// calculate the keyid
				MessageDigest md = MessageDigest.getInstance("SHA-384");
				keyId = new byte[20];
				System.arraycopy(md.digest(pubKey.getBytes()), 0, keyId, 0, keyId.length);
			} catch (Exception  e) {
				logger.error("ASN parse exception.", e);
			} finally {
				asnIn.close();
			}
		} catch (Exception  e) {
			logger.error("ASN parse exception.", e);
			derIn.close();
		} 
		return keyId;
	}
	
	/* Get authdata1 for EPID join process */
	private byte[] getEPIDAuthData1(String groupId) throws IOException {
		byte[] authData1 = new byte[26];
		byte[] groupIdBytes = Utils.base64Decode(groupId);
		if (null == groupIdBytes) {
			logger.error("GROUP ID base64 decode failed." + groupId);
			return null;
		}
		
		int index = 0;
		
		// algorithmID
		authData1[index] = 0x01;
		++ index;
		
		// keyID
		byte[] keyId = getKeyID();
		System.arraycopy(keyId, 0, authData1, 1, 20);
		index += 20;
		
		// requestedVid
		authData1[index] = groupIdBytes[3];
		authData1[index + 1] = groupIdBytes[4];
		authData1[index + 2] = groupIdBytes[5];
		authData1[index] = (byte) (authData1[index] & 0x0f);
		index += 3;
		
		// requestPid
		authData1[index] = groupIdBytes[6];
		authData1[index + 1] = groupIdBytes[7];
		
		return authData1;
	}
	
	/* The first step for requesting EPID certification */
	protected JSONObject requestEpidCertificationStep1(HttpSession session, E_KYC kyc) throws Exception {
		JSONObject responseJson = null;
		
		EpidMapper epidMapper = sqlSession.getMapper(EpidMapper.class);
		String groupId = epidMapper.selectGroupIdByKyc(kyc.toString());
    	if (null == groupId) {
    		logger.error("Function requestEpidCertificationStep1:select group id for kyc " + kyc.toString() + " failed.");
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SERVER_ERROR.toString());
			responseJson.put("description", "Group for kyc mismatch.");
			return responseJson;
		}
    	
    	// Combine authdata1
    	byte[] authData1 = getEPIDAuthData1(groupId);
    	if (null != authData1) {
    		ByteBuffer byteBuf = ByteBuffer.allocate(4 + 2 + authData1.length);
    		byteBuf.putInt(1);										// authId:1 – CAK authenticator
    		byteBuf.putShort((short) authData1.length);				// authData1 _LV:length
    		byteBuf.put(authData1);									// authData1 _LV:value
    		
    		String url = "https://join.epid-sbx.trustedservices.intel.com:443/v2/joinStart";
	    	ImmutablePair<Integer, byte[]> postRslt = EpidConnFactory.getInstance().httpPost(url, byteBuf.array());
	    	
	    	logger.trace("POST RESULT:" + postRslt.getLeft() + ".");
	    	int respStatus = postRslt.left;
	    	if (200 == respStatus) {
	    		// step1 response
	    		byte[] step1Resp = postRslt.getRight();
	    		session.setAttribute(EPIDController.EPID_JOIN_STEP1_RESPONSE_ATTR_NAME, step1Resp);
	    		
	    		// public key
	    		byte[] epidPub = new byte[272];
	    		System.arraycopy(step1Resp, 25, epidPub, 0, epidPub.length);
	    		
	    		// issuerNonce
	    		byte[] issuerNonce = new byte[32];
	    		System.arraycopy(step1Resp, 297, issuerNonce, 0, issuerNonce.length);
	    		
	    		responseJson = new JSONObject();
				responseJson.put("errorCode", ErrorCode.ERROR_SUCCESS.toString());
				responseJson.put("description", "success.");
				responseJson.put("epidPub", Utils.base64Encode(epidPub));
				responseJson.put("issuerNonce", Utils.base64Encode(issuerNonce));
	    	} else {
	    		logger.info("EPID join step1 failed.ErrorCode:" + respStatus + ".");
	    		responseJson = new JSONObject();
				responseJson.put("errorCode", ErrorCode.ERROR_EPID_ISSUER_ERROR.toString());
				responseJson.put("description", "EPID issuer response code " + respStatus + ".");
	    	}
    	} else {
    		logger.error("AuthData1 generate failed.");
    		responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SERVER_ERROR.toString());
			responseJson.put("description", "Server inner error.");
    	}
    	
		return responseJson;
	}
	
	/* Get authdata3 for epid join process */
	private byte[] getEPIDAuthData3(byte[] nonce, byte[] joinRequestBytes) throws Exception {
		// concat nonce and joinRequest
		byte[] shaContent = new byte[nonce.length + joinRequestBytes.length];
		System.arraycopy(nonce, 0, shaContent, 0, nonce.length);
		System.arraycopy(joinRequestBytes, 0, shaContent, nonce.length, joinRequestBytes.length);

		// read certification
		byte[] derCert = null;
		InputStream derIn = Resources.getResourceAsStream("IOT_CAK_IssuingCA0_VendID160.der");
		try {
			derCert = derIn.readAllBytes();
		} catch (IOException e) {
			logger.error("Read Der cert failed.", e);
			throw e;
		} finally {
			derIn.close();
		}
		
		// sign
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(derCert);
		KeyFactory keyFactory = KeyFactory.getInstance("EC") ;
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec) ;
		Signature signature = Signature.getInstance("SHA384withECDSA");
		signature.initSign(privateKey);
		signature.update(shaContent);
		
		return signature.sign();
	}
	
	/* The second step for requesting EPID certification */
	protected JSONObject requestEpidCertificationStep2(int userId, byte[] step1Resp, String joinRequest) throws Exception {
		JSONObject responseJson = null;
    	
		// check joinRequest
		byte[] joinRequestBytes = Utils.base64Decode(joinRequest);
		if (null == joinRequestBytes) {
			responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
			responseJson.put("description", "The joinRequest is not valid.");
			return responseJson;
		}
		if ((128 != joinRequestBytes.length) && (196 != joinRequestBytes.length)) {
    		responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_REQUEST_PARAMETER_INVALID.toString());
			responseJson.put("description", "The joinRequest is not valid.");
			return responseJson;
		}
		
		// get the nonce of authData2
		byte[] nonce = new byte[36];
		System.arraycopy(step1Resp, 335, nonce, 0, nonce.length);
		
		// combine authData3
		byte[] authData3 = getEPIDAuthData3(nonce, joinRequestBytes);
    	if (null == authData3)  {
    		logger.error("AuthData3 generate failed.");
    		responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SERVER_ERROR.toString());
			responseJson.put("description", "Server inner error.");
			return responseJson;
    	}
    	
    	// combine request content
		int contentLen = step1Resp.length + 2 + authData3.length + 2 + joinRequestBytes.length;
		ByteBuffer reqContentBytes = ByteBuffer.allocate(contentLen);
		reqContentBytes.put(step1Resp);
		reqContentBytes.putShort((short) authData3.length);
		reqContentBytes.put(authData3);
		reqContentBytes.putShort((short) joinRequestBytes.length);
		reqContentBytes.put(joinRequestBytes);
		
    	// send request
    	String url = "https://join.epid-sbx.trustedservices.intel.com:443/v2/credential";
    	ImmutablePair<Integer, byte[]> postRslt = EpidConnFactory.getInstance().httpPost(url, reqContentBytes.array());
    	
    	// parse response
    	int respStatus = postRslt.left;
    	logger.trace("POST RESULT:" + postRslt.getLeft() + ".");
    	if (200 == respStatus) {
    		responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_SUCCESS.toString());
			responseJson.put("description", "success.");
			String partCert = Utils.base64Encode(postRslt.getRight());
			responseJson.put("credential", partCert);
    		
			byte[] groupIdBytes = new byte[16];
	    	System.arraycopy(step1Resp, 25, groupIdBytes, 0, groupIdBytes.length);
	    	
    		EpidMapper epidMapper = sqlSession.getMapper(EpidMapper.class);
	    	EpidData epidPara = new EpidData();
	    	epidPara.setUser_id(userId);
	    	epidPara.setEpid_part_certification(partCert);
	    	epidPara.setPublish_timestamp(Utils.getCurrentTime());
	    	epidPara.setGroup_id(Utils.base64Encode(groupIdBytes));
    		epidMapper.insertEPIDCer(epidPara);
    	} else {
    		logger.info("EPID join step2 failed.ErrorCode:" + respStatus + ".");
    		responseJson = new JSONObject();
			responseJson.put("errorCode", ErrorCode.ERROR_EPID_ISSUER_ERROR.toString());
			responseJson.put("description", "EPID issuer response code " + respStatus + ".");
    	}
	    	
		return responseJson;
	}
	
	/* Organize verifier's public keys to be easy to use format for user */
	protected JSONObject formatVerifierPubKey(List<EpidData> selectRslt) {
		JSONObject publicKeysJson = new JSONObject();
		JSONArray pubKeyArray = new JSONArray();
		String previousKyc = null;
		Iterator<EpidData> iter = selectRslt.iterator();
		while (iter.hasNext()) {
			EpidData data = iter.next();
			String kyc = data.getKyc();
			String pubKey = data.getGroup_pub_key();
			
			// For the first time, init previousKyc.
			if (null == previousKyc) {
				previousKyc = kyc;
			}
			
			// When kyc changes, insert current kyc's public key array.
			if (!previousKyc.equalsIgnoreCase(kyc)) {
				publicKeysJson.put(previousKyc, pubKeyArray);
				pubKeyArray = new JSONArray();
			}
			pubKeyArray.put(pubKey);
			previousKyc = kyc;
		}
		
		// Insert the latest kyc's public key array.
		publicKeysJson.put(previousKyc, pubKeyArray);
		
		return publicKeysJson;
	}
	
	/* Function: record BKs */
	@Transactional(propagation=Propagation.REQUIRED)
	public JSONObject insertBK(int userId, E_KYC kyc, JSONArray bks, String signatures) {
		JSONObject responseJson = null;
		BKMapper BKMapper = sqlSession.getMapper(BKMapper.class);
		BKData bkPara = new BKData();
		bkPara.setUser_id(userId);
		bkPara.setKyc(kyc.toString());
		bkPara.setSignature(signatures);
		BKData selectRslt = BKMapper.selectCertToAddBK(bkPara);
		if (null != selectRslt) {
			String groupIdHex = selectRslt.getGroup_id_hex();
			String partCert = selectRslt.getEpid_part_certification();
			bkPara.setGroup_id_hex(groupIdHex);
			bkPara.setEpid_part_certification(partCert);
			BKMapper.updateSignature(bkPara);
			
			Iterator<Object> iter = bks.iterator();
			while (iter.hasNext()) {
				String bk = (String) iter.next();
				String bkMd5 = DigestUtils.md5Hex(bk);
				bkPara.setBk(bk);
				bkPara.setBk_md5(bkMd5);
				BKMapper.insertBKToEPIDCer(bkPara);
			}
			
    		responseJson = new JSONObject();
    		responseJson.put("errorCode", ErrorCode.ERROR_SUCCESS.toString());
    		responseJson.put("description", "success.");
		} else {
    		responseJson = new JSONObject();
    		responseJson.put("errorCode", ErrorCode.ERROR_NO_RECORD_EXIST.toString());
    		responseJson.put("description", "No unsigned EPID certification exists for kyc " + kyc + ".");
		}
		
		return responseJson;
	}
	
	/* Parse BK from signature */
	public static String parseBKfromSig(String signature) {
		String bk = null;
		byte[] sigBytes = Utils.base64Decode(signature);
		if (null != sigBytes) {
			// The first 512 bits of signature is B, and the second 512 bits of signature is K.
			final int BKLen = 128;
			byte[] bkBytes = new byte[BKLen];
			System.arraycopy(sigBytes, 0, bkBytes, 0, BKLen);
			bk = Utils.base64Encode(bkBytes);
		}
		
		return bk;
	}
}

/* User defined exception: available certification exists */
class CertExistException extends RuntimeException {
	private static final long serialVersionUID = 1L;
}
