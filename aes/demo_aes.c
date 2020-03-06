#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
 
void main()
{
	unsigned char *key_string = "123456";
	AES_KEY  en_aes, de_aes;
	int i = 0;
	unsigned char out1[16] = {0};
	unsigned char out2[16] = {0};
	if (AES_set_encrypt_key(key_string, 128, &en_aes) < 0) {
		fprintf(stderr, "Unable to set encryption key in AES\n");
		return;
	}
	if (AES_set_decrypt_key(key_string, 128, &de_aes) < 0) {
		fprintf(stderr, "Unable to set encryption key in AES\n");
		return;
	}
	unsigned char temp[16] = {0};
	strcpy(temp, "123456");
	AES_encrypt(temp, out1, &en_aes);
	AES_decrypt(out1, out2, &de_aes);
	printf("encrypt = %s\ndecrypt = %s\n", temp, out2);
}
