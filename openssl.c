#include <janet.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

typedef enum { DECRYPT = 0, ENCRYPT = 1 } mode;

const char *encrypt(const EVP_CIPHER *cipher, mode mode,
                    const unsigned char *key, int key_length, FILE *in,
                    FILE *out) {
  const int iv_length = EVP_CIPHER_iv_length(cipher);
  const int is_aead = EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER;
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char tag[EVP_MAX_AEAD_TAG_LENGTH];

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return "failed to create EVP_CIPHER_CTX";
  }

  if (!EVP_CipherInit_ex2(ctx, cipher, NULL, NULL, mode, NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return "failed to initialize EVP_CIPHER_CTX";
  }

  int tag_length = 0;
  if (is_aead) {
    tag_length = EVP_CIPHER_CTX_get_tag_length(ctx);
  }

  long stop_at = -1;

  if (mode) {
    if (!RAND_bytes(iv, iv_length)) {
      EVP_CIPHER_CTX_free(ctx);
      return "failed to generate a random IV";
    }
    fwrite(iv, 1, iv_length, out);
  } else {
    if (fread(iv, 1, iv_length, in) < (size_t)iv_length) {
      EVP_CIPHER_CTX_free(ctx);
      return "failed to read IV from the file";
    }

    if (is_aead) {
      long current = ftell(in);
      if (fseek(in, -tag_length, SEEK_END) != 0) {
        EVP_CIPHER_CTX_free(ctx);
        return "failed to find tag in the file";
      }
      if (fread(tag, 1, tag_length, in) < (size_t)tag_length) {
        EVP_CIPHER_CTX_free(ctx);
        return "failed to read tag from the file";
      }
      if (fseek(in, current, SEEK_SET) != 0) {
        EVP_CIPHER_CTX_free(ctx);
        return "failed to seek back to ciphertext";
      }
      if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_length, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return "failed to set AEAD tag";
      }

      fseek(in, 0, SEEK_END);
      stop_at = ftell(in) - tag_length;
      fseek(in, current, SEEK_SET);
    }
  }

  if (is_aead) {
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_length, NULL)) {
      EVP_CIPHER_CTX_free(ctx);
      return "failed to set AEAD IV length";
    }
  }

  if (!EVP_CipherInit_ex2(ctx, NULL, key, iv, mode, NULL)) {
    EVP_CIPHER_CTX_free(ctx);
    return "failed to initialize EVP_CIPHER_CTX";
  }

  unsigned char inbuf[1024];
  unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
  for (;;) {
    int to_read = 1024;
    if (stop_at != -1) {
      long remaining = stop_at - ftell(in);
      if (remaining <= 0) {
        break;
      }
      if (remaining < 1024) {
        to_read = (int)remaining;
      }
    }

    int inlen = fread(inbuf, 1, to_read, in);
    if (inlen <= 0) {
      break;
    }
    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
      EVP_CIPHER_CTX_free(ctx);
      return "failed to update EVP_CIPHER_CTX";
    }
    fwrite(outbuf, 1, outlen, out);
  }

  int outlen = 0;
  if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
    EVP_CIPHER_CTX_free(ctx);
    return "decryption failed";
  }
  fwrite(outbuf, 1, outlen, out);

  if (mode == ENCRYPT && is_aead) {
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_length, tag)) {
      EVP_CIPHER_CTX_free(ctx);
      return "failed to get AEAD tag";
    }
    fwrite(tag, 1, tag_length, out);
  }

  EVP_CIPHER_CTX_free(ctx);
  return NULL;
}

const char *encrypt_with_file(const EVP_CIPHER *cipher, mode mode,
                              const unsigned char *key, int key_length,
                              const char *input, const char *output) {
  FILE *input_file = fopen(input, "rb");
  if (!input_file) {
    return "failed to open input file";
  }
  FILE *output_file = fopen(output, "wb");
  if (!output_file) {
    fclose(input_file);
    return "failed to open output file";
  }

  const char *error =
      encrypt(cipher, mode, key, key_length, input_file, output_file);
  if (error != NULL) {
    fclose(input_file);
    fclose(output_file);
    return error;
  }

  fclose(input_file);
  if (fclose(output_file)) {
    return "failed to write to the output file";
  }

  return NULL;
}

static Janet encrypt_des(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 3);

  JanetByteView key = janet_getbytes(argv, 0);
  if (key.len != 8) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv("DES key must be exactly 8 bytes");
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  JanetString input = janet_getstring(argv, 1);
  JanetString output = janet_getstring(argv, 2);

  const char *error = encrypt_with_file(EVP_des_cbc(), ENCRYPT, key.bytes,
                                        key.len, input, output);
  if (error) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv(error);
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  Janet *result = janet_tuple_begin(2);
  result[0] = janet_ckeywordv("ok");
  result[1] = janet_wrap_nil();
  return janet_wrap_tuple(janet_tuple_end(result));
}

static Janet decrypt_des(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 3);

  JanetByteView key = janet_getbytes(argv, 0);
  if (key.len != 8) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv("DES key must be exactly 8 bytes");
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  JanetString input = janet_getstring(argv, 1);
  JanetString output = janet_getstring(argv, 2);

  const char *error = encrypt_with_file(EVP_des_cbc(), DECRYPT, key.bytes,
                                        key.len, input, output);
  if (error) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv(error);
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  Janet *result = janet_tuple_begin(2);
  result[0] = janet_ckeywordv("ok");
  result[1] = janet_wrap_nil();
  return janet_wrap_tuple(janet_tuple_end(result));
}

static Janet encrypt_3des(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 3);

  JanetByteView key = janet_getbytes(argv, 0);
  if (key.len != 24) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv("3DES key must be exactly 24 bytes");
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  JanetString input = janet_getstring(argv, 1);
  JanetString output = janet_getstring(argv, 2);

  const char *error = encrypt_with_file(EVP_des_ede3_cbc(), ENCRYPT, key.bytes,
                                        key.len, input, output);
  if (error) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv(error);
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  Janet *result = janet_tuple_begin(2);
  result[0] = janet_ckeywordv("ok");
  result[1] = janet_wrap_nil();
  return janet_wrap_tuple(janet_tuple_end(result));
}

static Janet decrypt_3des(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 3);

  JanetByteView key = janet_getbytes(argv, 0);
  if (key.len != 24) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv("3DES key must be exactly 24 bytes");
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  JanetString input = janet_getstring(argv, 1);
  JanetString output = janet_getstring(argv, 2);

  const char *error = encrypt_with_file(EVP_des_ede3_cbc(), DECRYPT, key.bytes,
                                        key.len, input, output);
  if (error) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv(error);
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  Janet *result = janet_tuple_begin(2);
  result[0] = janet_ckeywordv("ok");
  result[1] = janet_wrap_nil();
  return janet_wrap_tuple(janet_tuple_end(result));
}

static Janet encrypt_aes(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 3);

  JanetByteView key = janet_getbytes(argv, 0);
  if (key.len != 16) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv("AES key must be exactly 16 bytes");
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  JanetString input = janet_getstring(argv, 1);
  JanetString output = janet_getstring(argv, 2);

  const char *error = encrypt_with_file(EVP_aes_128_gcm(), ENCRYPT, key.bytes,
                                        key.len, input, output);
  if (error) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv(error);
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  Janet *result = janet_tuple_begin(2);
  result[0] = janet_ckeywordv("ok");
  result[1] = janet_wrap_nil();
  return janet_wrap_tuple(janet_tuple_end(result));
}

static Janet decrypt_aes(int32_t argc, Janet *argv) {
  janet_fixarity(argc, 3);

  JanetByteView key = janet_getbytes(argv, 0);
  if (key.len != 16) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv("AES key must be exactly 16 bytes");
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  JanetString input = janet_getstring(argv, 1);
  JanetString output = janet_getstring(argv, 2);

  const char *error = encrypt_with_file(EVP_aes_128_gcm(), DECRYPT, key.bytes,
                                        key.len, input, output);
  if (error) {
    Janet *result = janet_tuple_begin(2);
    result[0] = janet_ckeywordv("error");
    result[1] = janet_cstringv(error);
    return janet_wrap_tuple(janet_tuple_end(result));
  }

  Janet *result = janet_tuple_begin(2);
  result[0] = janet_ckeywordv("ok");
  result[1] = janet_wrap_nil();
  return janet_wrap_tuple(janet_tuple_end(result));
}

static const JanetReg cfuns[] = {
    {"encrypt-des", encrypt_des, "(openssl/encrypt-des)"},
    {"decrypt-des", decrypt_des, "(openssl/decrypt-des)"},
    {"encrypt-3des", encrypt_3des, "(openssl/encrypt-3des)"},
    {"decrypt-3des", decrypt_3des, "(openssl/decrypt-3des)"},
    {"encrypt-aes", encrypt_aes, "(openssl/encrypt-aes)"},
    {"decrypt-aes", decrypt_aes, "(openssl/decrypt-aes)"},
    {NULL, NULL, NULL}};

JANET_MODULE_ENTRY(JanetTable *env) {
  OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
  if (legacy == NULL) {
    janet_panic("failed to load OpenSSL legacy provider");
  }
  OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
  if (def == NULL) {
    janet_panic("failed to load OpenSSL default provider");
  }

  janet_cfuns(env, "openssl", cfuns);
}
