#include <stdio.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdlib.h>

#define OUR_AES_BLOCK_SIZE AES_BLOCK_SIZE /* 16 */
struct aes_key_st encrypt_key, decrypt_key;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
static int ncs_key_init(unsigned char *key)
{
	if (AES_set_encrypt_key(key, 128, &encrypt_key) < 0) {
		printf("Unable to set encryption key in AES");
		return -1;
	}
	if (AES_set_decrypt_key(key, 128, &decrypt_key) < 0) {
		printf("Unable to set encryption key in AES");
		return -1;
	}
	printf("ENCRYPT key init OK!\n");
	return 0;
}
static uint8_t decode_getbyte(char c) 
{
	char *dict = "+/=";
	char *dict2 = "-_.";
	
    //if (c == '+') {
    if (c == dict[0] || c == dict2[0]) {
        return 62;
    //} else if (c == '/') {
    } else if (c == dict[1] || c == dict2[1]) {
        return 63;
    } else if (c <= '9') {
        return (uint8_t)(c - '0' + 52);
    //} else if (c == '=') {
    } else if(c == dict[2] || c == dict2[2]) {
        return 64;
    } else if (c <= 'Z') {
        return (uint8_t)(c - 'A');
    } else if (c <= 'z') {
        return (uint8_t)(c - 'a' + 26);
    } 
    return 64;
}

uint32_t base64_encode(const char *src, uint32_t srclen, char *dest, int url_safe) 
{
    uint8_t input[3];
    uint8_t output[4];
    uint32_t i;
    uint32_t index_src = 0;
    uint32_t index_dest = 0;
	
	char *dict = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	if(url_safe)
	{
		dict = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/.";
	}

    for (i = 0;i < srclen;i += 3) {
        input[0] = src[index_src++];
        output[0] = (uint8_t)((input[0] >> 2)&0x3f);
        dest[index_dest++] = dict[output[0]];

        if (index_src < srclen) {
            input[1] = src[index_src++];
            output[1] = (uint8_t)(((input[0] & 0x03) << 4) + ((input[1] >> 4)&0x0f));
            dest[index_dest++] = dict[output[1]];
        } else {
            output[1] = (uint8_t)((input[0] & 0x03) << 4);
            dest[index_dest++] = dict[output[1]];
            //dest[index_dest++] = '=';
            //dest[index_dest++] = '=';
            dest[index_dest++] = dict[64];
            dest[index_dest++] = dict[64];
            break;
        }

        if (index_src < srclen) {
            input[2] = src[index_src++];
            output[2] = (uint8_t)(((input[1] & 0x0f) << 2) + ((input[2] >> 6)&0x03));
            dest[index_dest++] = dict[output[2]];
        } else {
            output[2] = (uint8_t)((input[1] & 0x0f) << 2);
            dest[index_dest++] = dict[output[2]];
            //dest[index_dest++] = '=';
            dest[index_dest++] = dict[64];
            break;
        }

        output[3] = (uint8_t)(input[2] & 0x3f);
        dest[index_dest++] = dict[output[3]];
    }

    dest[index_dest] = 0;

    return index_dest;
}
uint32_t base64_decode(const char *src, uint32_t srclen, char *dest) 
{
    uint8_t data[4];
    uint32_t i;
    uint32_t index = 0;
	char paddingchar = '=';
	char paddingchar2 = '.';

    for (i=0; i<srclen; i+=4) {
        data[0] = decode_getbyte(src[i]);
        data[1] = decode_getbyte(src[i + 1]);
        dest[index++] = (data[0] << 2) + (data[1] >> 4);

        //if (src[i+2] != '=') {
        if (src[i+2] != paddingchar && src[i+2] != paddingchar2) {
            data[2] = decode_getbyte(src[i+2]);
            if(64 > data[2])
			{
            	dest[index++] = ((data[1] & 0x0f) << 4) + (data[2] >> 2);
            }
        }

        //if (src[i+3] != '=') {
        if (src[i+3] != paddingchar && src[i+3] != paddingchar2) {
            data[3] = decode_getbyte(src[i + 3]);
			if(64 > data[3])
			{
            	dest[index++] = ((data[2] & 0x03) << 6) + (data[3]&0x3f);
			}
        }
    }

    dest[index] = '\0';

    return index;
}

static int ncs_encrypt(unsigned char *in, unsigned char *out)
{
	char *input, *output, *tmpin, *tmpout = NULL;
	int inputlen, inlen = 0;
	int padding = 0;
	int i;
	/* get aes in string */
	printf("in %s\n", in);
	inlen = strlen(in);
	inputlen = (((inlen + OUR_AES_BLOCK_SIZE)/OUR_AES_BLOCK_SIZE)*OUR_AES_BLOCK_SIZE);
	input = (char*)malloc(inputlen + 1);
	if (input == NULL) {
		return -1;
	}
	memset((void *)input, 0, inputlen + 1);
	output = (char*)malloc(inputlen + 1);
	if (output == NULL) {
		return -1;
	}
	memset((void *)output, 0, inputlen + 1);
	
	strcpy(input, in);

	padding = inputlen - inlen;
	for (i = 0; i < padding; i++) { /* pkcs7padding */
		input[inlen + i] = padding;
	}

	/* aes ecb */
	i = 0;
	tmpin = input;
	tmpout = output;
	while (i < inputlen) {
		//AES_ecb_encrypt(tmpin, tmpout, &encrypt_key, AES_ENCRYPT);
		AES_encrypt(tmpin, tmpout, &encrypt_key);
		tmpin += OUR_AES_BLOCK_SIZE;
		tmpout += OUR_AES_BLOCK_SIZE;
		i += OUR_AES_BLOCK_SIZE;
	}

	base64_encode(output, inputlen, out, 0);
	printf("encode %s; len %d;\n", out, strlen(out));
	return 0;
}
static int ncs_decrypt(unsigned char *in, unsigned char *out)
{
	const char *data_en;
	char data[4096] = {0};
	char *input, *output, *tmpin, *tmpout = NULL;
	int inputlen, inlen = 0;
	int i, j;
	int padding = 0;

	int padding_len, de_len;
	data_en = in;

	for (i = 0, j =0; i < strlen(data_en); i++) {
		if (data_en[i] != '"') {
			data[j++] = data_en[i];
		}
	}
	printf("decode %s; len %d;\n", data, strlen(data));
	inlen = strlen(data);
	input = (char*)malloc(inlen + OUR_AES_BLOCK_SIZE);
	if (input == NULL) {
		return -1;
	}
	memset((void *)input, 0, inlen + OUR_AES_BLOCK_SIZE);
	output = (char*)malloc(inlen + OUR_AES_BLOCK_SIZE);
	if (output == NULL) {
		return -1;
	}
	memset((void *)output, 0, inlen + OUR_AES_BLOCK_SIZE);
	de_len = base64_decode(data, inlen, input);
	padding_len = (((de_len+OUR_AES_BLOCK_SIZE-1)/OUR_AES_BLOCK_SIZE)*OUR_AES_BLOCK_SIZE);
	i = 0;
	tmpin = input;
	tmpout = output;
	while (i < inlen) {
		AES_decrypt(tmpin, tmpout, &decrypt_key);
		tmpin += OUR_AES_BLOCK_SIZE;
		tmpout += OUR_AES_BLOCK_SIZE;
		i += OUR_AES_BLOCK_SIZE;
	}
	padding = output[padding_len -1];
	for (i = 0; i < padding; i++) {
		output[padding_len-i-1] = 0;
	}
	printf("out %s\n", output);

	return 0;
}

int ncs_encrypt_decrypt_test(void)
{
	unsigned char data[16] = "1234567890";
	unsigned char endata[256] = {0};
	unsigned char dedata[256] = {0};
	int i = 0;
	ncs_key_init("5c44crn9ap98api7");
	ncs_encrypt(data, endata);
	ncs_decrypt(endata, dedata);
	return 0;
}

void main()
{
	ncs_encrypt_decrypt_test();
}
