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
import org.apache.ibatis.annotations.Update;

public interface EpidMapper {
	@Select("with TRANSNO as (SELECT @rowno:=@rowno + 1 AS rowno,TRAN.user_id, TRAN.publish_timestamp " 
			+ "FROM coconut.TBL_epid_certification_info as TRAN,(SELECT @rowno:=0) rowNum "
			+ "where user_id = #{user_id} order by TRAN.publish_timestamp desc) "
			+ "select TRANSNO.publish_timestamp,AUTH.epid_request_attempt_times_max "
			+ "from TRANSNO left join coconut.TBL_user_info as AUTH on TRANSNO.user_id=AUTH.user_id "
			+ "where TRANSNO.rowno = AUTH.epid_request_attempt_times_max;")
	@Results({
		@Result(property="publish_timestamp",column="publish_timestamp"), 
		@Result(property="epid_request_attempt_times_max",column="epid_request_attempt_times_max")
		})
	public EpidData selectMaxAttemptTimestamp(EpidData data);
	
	@Insert("insert into coconut.TBL_epid_certification_info(user_id,group_id,epid_part_certification,publish_timestamp) "
			+ "values(#{user_id},#{group_id},#{epid_part_certification},#{publish_timestamp});") 
    public int insertEPIDCer(EpidData data);
	
	@Select("select epid_part_certification from coconut.TBL_epid_certification_info as CER "
			+ "left join coconut.TBL_group_info as GROUPINFO "
			+ "on CER.group_id=GROUPINFO.group_id "
			+ "where CER.revoke_flag=0 and CER.user_id=#{user_id} and GROUPINFO.kyc=#{kyc};")
	public String selectEpidCer(EpidData data);				//kyc user_id
	
	@Update("update coconut.TBL_epid_certification_info as CER "
			+ "left join coconut.TBL_group_info as CERGRP on CER.group_id=CERGRP.group_id "
			+ "set CER.revoke_flag=1 where CER.user_id=#{user_id} and CERGRP.kyc=#{kyc};")
	public int revokeCer(EpidData epidData);				//para:int user_id, String kyc
	
	@Select("select distinct verifier,kyc "
			+ "from coconut.TBL_business_info order by verifier;")
	@Results({
		@Result(property="verifier",column="verifier"), 
		@Result(property="kyc",column="kyc")
		})
	public List<EpidData> selectBusiness();	
	
	@Select("select distinct GRP.group_pub_key,GRP.kyc "
			+ "from coconut.TBL_group_info as GRP left join coconut.TBL_business_info as BUS on GRP.kyc=BUS.kyc "
			+ "where BUS.verifier=#{verifier} order by GRP.kyc;")
	@Results({
		@Result(property="group_pub_key",column="group_pub_key"), 
		@Result(property="kyc",column="kyc")
		})
	public List<EpidData> selectVerifierPubKey(String verifier);	
	
	@Select("select group_id from coconut.TBL_group_info where kyc=#{kyc} limit 1;")
	public String selectGroupIdByKyc(String kyc);	
	
}
