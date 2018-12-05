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

public class BKData {
	private int user_id;
	private String kyc;
	private String bk;
	private String bk_md5;
	private String epid_part_certification;
	private String group_id;
	private String group_id_hex;
	private String signature;
	
	public String getGroup_id_hex() {
		return group_id_hex;
	}
	public void setGroup_id_hex(String group_id_hex) {
		this.group_id_hex = group_id_hex;
	}
	public int getUser_id() {
		return user_id;
	}
	public void setUser_id(int user_id) {
		this.user_id = user_id;
	}
	public String getKyc() {
		return kyc;
	}
	public void setKyc(String kyc) {
		this.kyc = kyc;
	}
	public String getBk() {
		return bk;
	}
	public void setBk(String bk) {
		this.bk = bk;
	}
	public String getBk_md5() {
		return bk_md5;
	}
	public void setBk_md5(String bk_md5) {
		this.bk_md5 = bk_md5;
	}
	public String getEpid_part_certification() {
		return epid_part_certification;
	}
	public void setEpid_part_certification(String epid_part_certification) {
		this.epid_part_certification = epid_part_certification;
	}
	public String getGroup_id() {
		return group_id;
	}
	public void setGroup_id(String group_id) {
		this.group_id = group_id;
	}
	public String getSignature() {
		return signature;
	}
	public void setSignature(String signature) {
		this.signature = signature;
	}
	
}
