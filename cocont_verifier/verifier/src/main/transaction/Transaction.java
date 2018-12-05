/* Notice: This part code is out of the coconut's core function. It is supplied as a demo. 
 * So it should not be used in production environment. */
package main.transaction;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import coconut.epidasdk.Verifier;

@Controller
public class Transaction {
	private String[] basenameArray = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};

	private byte[] base64Decode(String text) {
		byte[] textByte = null;
		
		if (null != text) {
			if (0 == (text.length()%4) ) {
				Base64.Decoder b64Decoder = Base64.getDecoder();
				try {
					textByte = b64Decoder.decode(text);
				} catch (IllegalArgumentException e) {
					e.printStackTrace();
				}
			}
		}
		
		return textByte;
	}
	
	private boolean baseNameCheck(String basename) {
		boolean result = false;
		for (int index = 0; index < basenameArray.length; index ++) {
			if (basenameArray[index].equals(basename)) {
				result = true;
			}
		}
		
		return result;
	}
	
	@RequestMapping("/coconutTXHanding")
	@ResponseBody
	public String coconutTXHanding(HttpServletRequest request) throws IOException, NoSuchAlgorithmException {
		String responseContent = null;
		
		InputStream requestStream = request.getInputStream();
		String requestContent = null;
		try {
			requestContent = new String(requestStream.readAllBytes());
			System.out.println("txData:" + requestContent);
		} catch (IOException e) {
			throw e;
		} finally {
			requestStream.close();
		}
		
		JSONObject requestJson = null;
		try {
			requestJson = new JSONObject(requestContent);
		} catch (JSONException e) {
			responseContent = "Request Content is not a json.";
			return responseContent;
		}
		
		if(!(requestJson.has("groupId") && requestJson.has("basename") && requestJson.has("signature") && requestJson.has("msg"))) {
			responseContent = "Parameter missing.";
			return responseContent;
		} 
		
		String groupId = requestJson.getString("groupId");
		
		String basename = requestJson.getString("basename");
		if (!baseNameCheck(basename)) {
			responseContent = "Parameter basename is invalid.";
			return responseContent;
		}
		
		String signature = requestJson.getString("signature");
		byte[] signatureBytes = base64Decode(signature);
		if (null == signatureBytes) {
			responseContent = "Parameter signature is invalid.";
			return responseContent;
		}
		
		String msg = requestJson.getString("msg");
		byte[] msgBytes = base64Decode(msg);
		if (null == msgBytes) {
			responseContent = "Parameter msgBytes is invalid.";
			return responseContent;
		}
		
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		Date localDate = new Date();
		String timestamp = dateFormat.format(localDate);
		MessageDigest md5Dig = MessageDigest.getInstance("MD5");
		String md5 = printHexString(md5Dig.digest((signature + timestamp).getBytes()));
		
		String path = this.getClass().getClassLoader().getResource("/").getPath();
		System.out.println("VERIFIER PATH:" + path);
		
		String sigFileDir = path + "/" + groupId + "/signature/";
		File file = new File(sigFileDir);
		if ((!file.exists()) || (!file.isDirectory())) {
			file.mkdirs();
		}
		String sigFileName = sigFileDir + md5;
		FileOutputStream sigOut = new FileOutputStream(sigFileName);
		try {
			sigOut.write(signatureBytes);
		} catch (IOException e) {
			throw e;
		} finally {
			sigOut.close();
		}
		
		String msgFileDir = path + "/" + groupId + "/msg/";
		file = new File(msgFileDir);
		if ((!file.exists()) || (!file.isDirectory())) {
			file.mkdirs();
		}
		
		String msgFileName = msgFileDir + md5;
		FileOutputStream msgOut = new FileOutputStream(msgFileName);
		try {
			msgOut.write(msgBytes);
		} catch (IOException e) {
			throw e;
		} finally {
			msgOut.close();
		}
		
		Verifier verifier = new Verifier();
		int verifyRslt = verifier.VerifySignature(path, sigFileName, msgFileName, basename);
		if (0 == verifyRslt) {
			responseContent = "success.";
		} else {
			responseContent = "Verificaiton not pass.ErrorCode:" + verifyRslt + ".";
		}
		
		file = new File(sigFileName);
		file.deleteOnExit();
		file = new File(msgFileName);
		file.deleteOnExit();
		
		return responseContent;
	}
	
	private String printHexString(byte[] bytes) {    
		StringBuffer strBuf = new StringBuffer();
	    for (int i = 0; i < bytes.length; i++) {    
		     String hex = Integer.toHexString(bytes[i] & 0xFF);    
		     if (hex.length() == 1) {    
		       hex = '0' + hex;    
		     }    
		     strBuf.append(hex);
	    }    
		
	    return strBuf.toString();
	} 

}
