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

import org.json.JSONObject;

import coconut.svcsdk.kyc.KYCController.E_KYC;

/* Client data parsed from request body */
public class ClientParsedData {
	private int user_id;
	private E_KYC kyc;
	private JSONObject clientReq;
	
	public JSONObject getClientReq() {
		return clientReq;
	}
	public void setClientReq(JSONObject clientReq) {
		this.clientReq = clientReq;
	}
	public int getUser_id() {
		return user_id;
	}
	public void setUser_id(int user_id) {
		this.user_id = user_id;
	}
	public E_KYC getKyc() {
		return kyc;
	}
	public void setKyc(E_KYC kyc) {
		this.kyc = kyc;
	}
	
}

