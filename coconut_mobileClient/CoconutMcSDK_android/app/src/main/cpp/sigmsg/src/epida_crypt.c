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
 * \encryption and decryption interfaces
 */

/* system header files */
#include <stdio.h>
#include <stdlib.h>

/* epida common header files */
#include "include/epida_define.h"

/* third party library header files */
#include "openssl/aes.h"
#include "openssl/evp.h"

#define AES256_KEY_SIZE            (32)
#define AES256_ROUND_NUM           (5)
#define ENCRYPT_DATA_MAX_LEN       (10 * 1024)
#define DECRYPT_DATA_MAX_LEN       (20 * 1024)


UINT32 g_key_salt[] = {45678, 87654};

/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
static INT32 encrypt_init(unsigned char *passphrase, int passphrase_len,
                        unsigned char *salt, EVP_CIPHER_CTX *cipher_ctx)
{
    INT32 key_size;
    UCHAR key[32];
    UCHAR iv[32];

    /*
     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
     * nrounds is the number of times the we hash the material. More rounds are more secure but
     * slower.
     */
    key_size = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, passphrase, passphrase_len,
                              AES256_ROUND_NUM, key, iv);
    if (AES256_KEY_SIZE != key_size)
    {
        return EPIDA_ERR;
    }

    if (0 == EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        return EPIDA_ERR;
    }

    return EPIDA_OK;
}

static INT32 decrypt_init(UCHAR *passphrase, INT32 passphrase_len,
                          UCHAR *salt, EVP_CIPHER_CTX *cipher_ctx)
{
    INT32 key_size;
    UCHAR key[32];
    UCHAR iv[32];

    /*
     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
     * nrounds is the number of times the we hash the material. More rounds are more secure but
     * slower.
     */
    key_size = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, passphrase, passphrase_len,
                              AES256_ROUND_NUM, key, iv);
    if (AES256_KEY_SIZE != key_size)
    {
        return EPIDA_ERR;
    }

    if (0 == EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        return EPIDA_ERR;
    }

    return EPIDA_OK;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
UCHAR* do_encrypt(UCHAR *passphrase, INT32 passphrase_len,
                          UCHAR *plain_data, INT32 *len)
{
    EVP_CIPHER_CTX* cipher_ctx = NULL;
    INT32 cipher_data_len = 0;
    INT32 final_cipher_data_len = 0;
    UCHAR *cipher_data = NULL;
    INT32 ret = EPIDA_OK;


    if ( (NULL == passphrase) || (passphrase_len <= 0)
            || (NULL == plain_data)  || (NULL == len)
            || (*len <= 0) || (*len > ENCRYPT_DATA_MAX_LEN) )
    {
        return NULL;
    }

    /* max cipher_data len for a n bytes of plain_data is n + AES_BLOCK_SIZE -1 bytes */
    do
    {
        cipher_ctx = EVP_CIPHER_CTX_new();
        if (NULL == cipher_ctx)
        {
            ret = EPIDA_ERR;
            break;
        }

        if (encrypt_init(passphrase, passphrase_len, (unsigned char*)g_key_salt, cipher_ctx) < 0)
        {
            ret = EPIDA_ERR;
            break;
        }

        cipher_data_len = *len + AES_BLOCK_SIZE;
        cipher_data = malloc(cipher_data_len);
        if (NULL == cipher_data)
        {
            ret = EPIDA_ERR;
            break;
        }

        /* update cipher_data, c_len is filled with the length of cipher_data generated,
          *len is the size of plain_data in bytes */
        if (0 == EVP_EncryptUpdate(cipher_ctx, cipher_data, &cipher_data_len, plain_data, *len))
        {
            ret = EPIDA_ERR;
            break;
        }

        /* update cipher_data with the final remaining bytes */
        if (0 == EVP_EncryptFinal_ex(cipher_ctx, cipher_data + cipher_data_len, &final_cipher_data_len))
        {
            ret = EPIDA_ERR;
            break;
        }
    }while(0);

    if (EPIDA_OK != ret)
    {
        *len = 0;
        EPIDA_SAFE_FREE(cipher_data);
    }
    else
    {
        *len = cipher_data_len + final_cipher_data_len;
    }

    if (NULL != cipher_ctx)
    {
        EVP_CIPHER_CTX_free(cipher_ctx);
        cipher_ctx = NULL;
    }

    return cipher_data;
}

/*
 * Decrypt *len bytes of cipher_data
 */
UCHAR* do_decrypt(UCHAR *passphrase, INT32 passphrase_len, UCHAR *cipher_data, INT32 *len)
{
    EVP_CIPHER_CTX* cipher_ctx = NULL;
    UCHAR *plain_data = NULL;
    INT32 plain_data_len = 0;
    INT32 final_plain_data_len = 0;
    INT32 ret = EPIDA_OK;

    if ( (NULL == passphrase) || (passphrase_len <= 0) || (NULL == cipher_data)
          || (NULL == len) || (*len <= 0) || (*len > DECRYPT_DATA_MAX_LEN) )
    {
        return NULL;
    }

    /* plain_data will always be equal to or lesser than length of cipher_data */
    do
    {
        cipher_ctx = EVP_CIPHER_CTX_new();
        if (NULL == cipher_ctx)
        {
            ret = EPIDA_ERR;
            break;
        }

        if (decrypt_init(passphrase, passphrase_len, (unsigned char*)g_key_salt, cipher_ctx) < 0)
        {
            ret = EPIDA_ERR;
            break;
        }

        plain_data_len = *len;
        plain_data = malloc(plain_data_len);
        if (NULL == plain_data)
        {
            ret = EPIDA_ERR;
            break;
        }

        if (0 == EVP_DecryptUpdate(cipher_ctx, plain_data, &plain_data_len, cipher_data, *len))
        {
            ret = EPIDA_ERR;
            break;
        }

        if (0 == EVP_DecryptFinal_ex(cipher_ctx, plain_data + plain_data_len, &final_plain_data_len))
        {
            ret = EPIDA_ERR;
            break;
        }
    }while(0);

    if (EPIDA_OK != ret)
    {
        *len = 0;
        EPIDA_SAFE_FREE(plain_data);
    }
    else
    {
        *len = plain_data_len + final_plain_data_len;
    }

    if (NULL != cipher_ctx)
    {
        EVP_CIPHER_CTX_free(cipher_ctx);
        cipher_ctx = NULL;
    }

    return plain_data;
}
