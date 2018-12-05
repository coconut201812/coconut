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
package coconut.svcsdk.mapper;

public class EpidData {
	private int user_id;
	private String publish_timestamp;
	private int epid_request_attempt_times_max;
	private String kyc;
	private String group_id;
	private String epid_part_certification;
	private String basenames;
	private String bk;
	private String signature;
	private String verifier;
	private String verifier_address;
	private String group_pub_key;

	public String getGroup_pub_key() {
		return group_pub_key;
	}
	public void setGroup_pub_key(String group_pub_key) {
		this.group_pub_key = group_pub_key;
	}
	public String getVerifier_address() {
		return verifier_address;
	}
	public void setVerifier_address(String verifier_address) {
		this.verifier_address = verifier_address;
	}
	public String getVerifier() {
		return verifier;
	}
	public void setVerifier(String verifier) {
		this.verifier = verifier;
	}
	public String getBk() {
		return bk;
	}
	public void setBk(String bk) {
		this.bk = bk;
	}
	public String getSignature() {
		return signature;
	}
	public void setSignature(String signature) {
		this.signature = signature;
	}
	public String getBasenames() {
		return basenames;
	}
	public void setBasenames(String basenames) {
		this.basenames = basenames;
	}
	public String getKyc() {
		return kyc;
	}
	public void setKyc(String kyc) {
		this.kyc = kyc;
	}
	public String getGroup_id() {
		return group_id;
	}
	public void setGroup_id(String group_id) {
		this.group_id = group_id;
	}
	public String getEpid_part_certification() {
		return epid_part_certification;
	}
	public void setEpid_part_certification(String epid_part_certification) {
		this.epid_part_certification = epid_part_certification;
	}
	public int getEpid_request_attempt_times_max() {
		return epid_request_attempt_times_max;
	}
	public void setEpid_request_attempt_times_max(int epid_request_attempt_times_max) {
		this.epid_request_attempt_times_max = epid_request_attempt_times_max;
	}
	public int getUser_id() {
		return user_id;
	}
	public void setUser_id(int user_id) {
		this.user_id = user_id;
	}
	public String getPublish_timestamp() {
		return publish_timestamp;
	}
	public void setPublish_timestamp(String publish_timestamp) {
		this.publish_timestamp = publish_timestamp;
	}
	
}
