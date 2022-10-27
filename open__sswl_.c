#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

EVP_PKEY_CTX * HKDF_Extract(unsigned char initial_salt, unsigned char client_dst_connection_id);

int main(){
        EVP_PKEY_CTX *initial_secret;
        unsigned char initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a;
        unsigned char client_dst_connection_id = 0x8394c8f03e515708;

        initial_secret = HKDF_Extract(initial_salt, client_dst_connection_id);
        //printf("%02x\n",initial_secret);

        return 0;
}

EVP_PKEY_CTX * HKDF_Extract(unsigned char initial_salt, unsigned char client_dst_connection_id){

        EVP_PKEY_CTX *pctx;
        unsigned char out[32];
        size_t outlen = sizeof(out);
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

        EVP_PKEY_CTX_set1_hkdf_salt(pctx, initial_salt, 32);  /initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a/
        EVP_PKEY_CTX_set1_hkdf_key(pctx, client_dst_connection_id, 32); /client_dst_connection_id = 0x8394c8f03e515708/

        return pctx;

}