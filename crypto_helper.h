#ifndef KEYMASTER_H
#define KEYMASTER_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>

#include "log.h"

#define AES_GCM_256_IV_LEN 16
#define AES_GCM_256_KEY_LEN 32
#define AES_GCM_256_TAG_LEN 16
#define SHA256_DEFAULT_SIZE 32
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2

int EncryptDecrypt(int mode, char *in, size_t in_len, char *key,
                   char *iv, char* tag, char *out, size_t *out_len);


#endif // KEYMASTER_H
