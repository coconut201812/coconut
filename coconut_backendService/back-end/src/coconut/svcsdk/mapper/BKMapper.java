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

import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;

public interface BKMapper {
	// see if the group id exists in database
	@Select("select group_id_hex from coconut.TBL_group_info where group_id=#{group_id};")
	public String selectGroupIdHex(String group_id);
	
	// query BK on the basis of md5
	@Select("select BK.bk,BK.epid_part_certification "
			+ "from coconut.TBL_BK_info_${group_id_hex} as BK "
			+ "left join coconut.TBL_epid_certification_info as CERT on BK.epid_part_certification=CERT.epid_part_certification "
			+ "where BK.bk_md5=#{bk_md5} and CERT.revoke_flag=0;")
	@Results({
		@Result(property="bk",column="bk"), 
		@Result(property="epid_part_certification",column="epid_part_certification")
		})
	public List<BKData> selectBK(BKData bkData);
	
	// query the certification which BK is about to insert.
	@Select("select GRP.group_id_hex,CERT.epid_part_certification "
			+ "from coconut.TBL_epid_certification_info as CERT "
			+ "left join coconut.TBL_group_info as GRP on CERT.group_id = GRP.group_id "
			+ "where CERT.user_id=#{user_id} and GRP.kyc=#{kyc} and CERT.revoke_flag=0;")
	@Results({
		@Result(property="group_id_hex",column="group_id_hex"), 
		@Result(property="epid_part_certification",column="epid_part_certification")
		})
	public BKData selectCertToAddBK(BKData bkData);
	
	// record BK
	@Insert("insert into coconut.TBL_BK_info_${group_id_hex}(bk,bk_md5,epid_part_certification) "
			+ "values(#{bk},#{bk_md5},#{epid_part_certification});") 
    public int insertBKToEPIDCer(BKData data);
	
	// record signature
	@Insert("update coconut.TBL_epid_certification_info "
			+ "set signature=#{signature} where epid_part_certification=#{epid_part_certification};") 
    public int updateSignature(BKData data);
}
