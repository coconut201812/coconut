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

public enum ErrorCode {
		ERROR_SUCCESS,
		ERROR_SESSION_INVALID,
		ERROR_REQUEST_PARAMETER_WRONG,
		ERROR_REQUEST_NONEXISTENT_KYC,
		ERROR_REQUEST_PARAMETER_INVALID, 
		ERROR_NO_RECORD_EXIST,
		ERROR_REQUEST_TOO_OFTEN,
		ERROR_EMAIL_INVALID,
		ERROR_PASSWORD_INVALID,
		ERROR_CAPTCHA_INVALID,
		ERROR_KYC_INUSE,
		ERROR_KYC_CONNECT,
		ERROR_DATABASE_ERROR,
		ERROR_SERVER_ERROR,
		ERROR_CONNECTION,
		ERROR_EMAIL_SEND,
		ERROR_SMS_SEND,
		ERROR_CAPTCHA_ERR_TOO_MUCH,
		ERROR_JOIN_STEP1_ABSENT, 
		ERROR_EPID_ISSUER_ERROR
}
