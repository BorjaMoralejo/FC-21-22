#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

void print_hex(uint8_t *buf, uint32_t c);
uint32_t hexdigit_value(uint8_t c);
void parse(uint32_t length, uint8_t *in, uint8_t *out);


int main(int argc, char *argv[])
{
	struct AES_ctx ctx;
	uint8_t iv[AES_BLOCKLEN];
	uint8_t key[AES_KEYLEN];
	uint8_t enc_text[AES_BLOCKLEN];
	FILE *fd_in, *fd_out;
	
    	uint32_t total_bytes = 0;
    	uint64_t size;
	uint8_t padding;
    	uint32_t read_bytes;

	
	if(argc != 4)
	{
		fprintf(stderr, "Usage: %s source_file dest_file key(hex)\n", argv[0]);
		return(0);
	}
	if((fd_in = fopen(argv[1],"r")) == 0)
	{
		fprintf(stderr, "Error opening input file %s\n", argv[1]);
		return(0);
	}
	if((fd_out = fopen(argv[2],"w+")) == 0)
	{
		fprintf(stderr, "Error opening output file %s\n", argv[2]);
		return(0);
	}
	parse(AES_KEYLEN, argv[3], key);
	
	read_bytes = fread(iv, 1, AES_BLOCKLEN, fd_in);
	AES_init_ctx_iv(&ctx, key, iv);
	total_bytes += read_bytes;
	
	while((read_bytes = fread(enc_text, 1, AES_BLOCKLEN, fd_in)) > 0)
	{
        	total_bytes += read_bytes;
		AES_CBC_decrypt_buffer(&ctx, enc_text, AES_BLOCKLEN);
		
		if(total_bytes == size)
		    	fwrite(enc_text, 1, AES_BLOCKLEN - enc_text[AES_BLOCKLEN - 1], fd_out);
		else if (total_bytes > AES_BLOCKLEN)
	  		fwrite(enc_text, 1, AES_BLOCKLEN, fd_out);
	}
	fclose(fd_in);
	fclose(fd_out);
}

void print_hex(uint8_t *buf, uint32_t c)
{
    uint32_t i;
    for(i = 0; i < c; i++){
        printf("%x", buf[i]);
    }
    printf("\n");
}

uint32_t hexdigit_value(uint8_t c)
{
    int nibble = -1;
    if(('0' <= c) && (c <= '9')) 
        nibble = c-'0';
    if(('a' <= c) && (c <= 'f'))
        nibble = c-'a' + 10;
    if(('A' <= c) && (c <= 'F'))
        nibble = c-'A' + 10;
    return nibble;
}
void parse(uint32_t length, uint8_t *in, uint8_t *out)
{
    uint32_t i, shift, idx;
    uint8_t nibble, c;
    uint32_t len = strlen(in);
    if(length >(len/2))
        length = (len/2);
    memset(out, 0, length);
    for(i = 0;i < length * 2;i++)
    {
        shift = 4 - 4 * (i & 1);
        idx = i;//len-1-i;
        c = in[idx];
        nibble = hexdigit_value(c);
        out[i/2] |= nibble << shift;
    }
}
