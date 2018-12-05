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
/*!
* \file
* \brief AES256 encrypt/decrypt interface.
*/

#ifndef _EPIDA_CRYPT_H_
#define _EPIDA_CRYPT_H_

extern unsigned char *do_encrypt(unsigned  char* passphrase, int passphrase_len, unsigned char *plain_data, int *len);

extern unsigned char *do_decrypt(unsigned  char* passphrase, int passphrase_len, unsigned char *cipher_data, int *len);

#endif
