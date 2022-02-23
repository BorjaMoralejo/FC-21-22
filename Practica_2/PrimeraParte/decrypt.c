#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "aes.h"
#include "iaesni.h"

#define BLOCK_SIZE 16
#define AES_KEY_LENGTH 32
#define KEY_LENGTH 32 
#define RANGE 256

uint8_t aux[BLOCK_SIZE];

uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

void print_hex(uint8_t *buf, uint32_t c)
{
    uint32_t i;

    for(i = 0; i < c; i++)
    {
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

uint32_t parse_mask(uint8_t *in, int64_t **key_mask){
    
    uint64_t i = 0;                                                                                                                             
    uint32_t n_masks = 0;                                                                                                                      
    char *end_ptr;                                                                                                                         
    uint8_t *in_aux = strdup(in);                                                                                                     
    uint8_t *pt = strtok (in_aux,"_");                                                                                                    
    while (pt != NULL) 
    {                                                                                                                   
        if(strtol(pt, &end_ptr, 10) == -1)
        {
            n_masks = 0;
            return(n_masks);
        }
        n_masks++;                                                                                                                        
        pt = strtok (NULL, "_");                                                                                                           
    }                                                                                                                                      
    *key_mask = malloc(n_masks * sizeof(int64_t));                                                                                               
                                                                                                                                           
    pt = strtok (in, "_");                                                                                                              
    while (pt != NULL) 
    {                                                                                                                   
        (*key_mask)[i++] = strtol(pt, &end_ptr, 10);                                                                                            
        pt = strtok (NULL, "_");                                                                                                           
    }                                                                                                                                      
    return(n_masks);                                                                                                                      
}

// Imprime en pantalla el string Texto y el tiempo de ejecucion (ms): t1-t0
void TiempoEjec (char *Texto, struct timespec *t0, struct timespec *t1)
{
 double tej;
 tej = (t1->tv_sec - t0->tv_sec) + (t1->tv_nsec - t0->tv_nsec) / (double)1e9;
 printf ("%s = %1.3f ms\n\n", Texto, tej*1000);
}

/*
 * Modifica la key utilizando la mascara y pasa por todas las combinaciones posibles (ASCII)
 * Devuelve -1 al terminar con todas las combinaciones, 0 en el caso contrario
 */
int redo_key(uint8_t *key, int64_t *key_mask, int64_t n_key_mask){
	
	int k = 0;
	char check = 0;
	while(check == 0 && k < n_key_mask)
	{
		check = 1;
		// Incrementando entre los valores ASCII
		if(key[ key_mask[k]] == 0x7A)  //0x7A
		{
			key[key_mask[k]] = 0x30; // 0x30
			k++;
			check = 0;
		}else key[ key_mask[k] ]++;
	}

	if(k == n_key_mask) return -1;

	return 0;	
}

int redo_plaintext(int64_t n_plaintext_mask, int64_t *plaintext_mask, uint8_t *plain_text){

	int check = 0;
	int k = 0;
	while(check == 0 && k < n_plaintext_mask)
	{
		check = 1;
		if(plain_text[plaintext_mask[k]] == 0xFF)
		{
			plain_text[plaintext_mask[k]] = 0x00;
			k++;
			check = 0;
		}else
			plain_text[plaintext_mask[k]]++;
		}
	if(k == n_plaintext_mask) return -1;

	return 0;
}

void print_key_plaintext(uint8_t *key, int64_t *key_mask, int64_t n_key_mask, uint8_t *plain_text){
	int k;

	printf("La key es: ");
	for(k = 0; k < 32; k++)
		printf("%c", key[k]);
	printf("\n");

	printf("key huecos: ");
	for(k = 0; k < n_key_mask; k++)
		printf("%c", key[key_mask[k]]);
	printf("\n");
			
	printf("m0: ");
	for(k = 0; k < 16; k++)
		printf("%02X", plain_text[k]);
	printf("\n");
}


void search(int64_t n_key_mask, int64_t *key_mask, int64_t n_plaintext_mask, int64_t *plaintext_mask, uint8_t *key, uint8_t *plain_text, uint8_t *cypher_text)
{	
	struct AES_ctx ctx;
	int i,j,k,n;
	char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	char iv_c[16];
	char plain_text_c[32];
	//char *plain_text_combi;
	char result[64];
	char check;
	char end = 0;
	struct timespec t0;
	struct timespec t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	


	// Inicializando clave a comienzo de busqueda (todo 0 en ascii)
	for(i = 0; i < n_key_mask; i++)
		key[key_mask[i]] = 0x30; // 0x30
	
	for(i = 0; i < n_plaintext_mask; i++)
		plain_text[plaintext_mask[i]] = 0x00; // 0x30

	memcpy(iv_c, iv, 16);
	while(end == 0)
	{
		check = 1;
		k = 0;
	
		memcpy(plain_text_c, plain_text, 16);

		#ifdef AESNI
        	enc_256_CBC(plain_text_c, result, key, iv_c, 4);
		memcpy(plain_text_c, result, 16);
		#else
		memcpy(iv_c, iv, 16);
		AES_init_ctx_iv(&ctx, key, iv_c);
		AES_CBC_encrypt_buffer(&ctx, plain_text_c, 16);
		#endif

		#ifdef DEBUG
			// Printeando el texto recien cifrado y el original
			printf("cypher_text: ");
			for(j = 0; j < 16; j++)
				printf("%02X", 0x000000FF & plain_text_c[j]);
			printf("\t");
			for(j = 0; j < 16; j++)
				printf("%02X", 0x000000FF & cypher_text[j]);
			printf("\n");
		#endif

		// Comprobar la parte cifrada, si coinciden, se acaba
		if ( memcmp(plain_text_c, cypher_text, 16) == 0)
			end = 1;
		else {
			// Cambiando la key a buscar
			end = redo_key(key, key_mask, n_key_mask);

			if(end == -1 && n_plaintext_mask != 0) 
			{
				//printf("Todas las keys probadas, pasando a incrementar m0\n");
				/*
				for(i = 0; i < n_plaintext_mask; i++)
					printf("%02X" ,plain_text[plaintext_mask[i]]); // 0x30
				printf("\n");
				*/
				// Resetear key y ciclar con el mensaje
				for(i = 0; i < n_key_mask; i++)
					key[key_mask[i]] = 0x30;
				// Cambiando el plaintext
				end = redo_plaintext(n_plaintext_mask, plaintext_mask, plain_text);
			}
		}
	}

	if(end == 1)
		print_key_plaintext(key, key_mask, n_key_mask, plain_text);
	else if(end == -1)
		printf("No se ha encontrado la clave y se han acabado las combinaciones");

	clock_gettime(CLOCK_MONOTONIC, &t1);
	TiempoEjec("Tiempo: ", &t0, &t1);
}


int main(int argc, char *argv[])
{

	int64_t n_key_mask;
	int64_t n_plaintext_mask;
	uint8_t key[AES_KEY_LENGTH];
	uint8_t plain_text[BLOCK_SIZE];
	uint8_t cypher_text[BLOCK_SIZE];
	int64_t *key_mask;
	int64_t *plaintext_mask;
	uint64_t n_threads, n_threads_sys;
	char *end_ptr;
	
	if(argc != 6 && argc != 7)
	{
		fprintf(stderr, "Usage: %s key key_mask plaintext plaintext_mask cyphertext\n", argv[0]);
		return(0);
	}
	if(argc == 6)
		n_threads = 1;
	else
	{
		n_threads_sys = sysconf(_SC_NPROCESSORS_ONLN);
		n_threads = strtol(argv[6], &end_ptr, 10);
		if(n_threads > n_threads_sys)
	    		n_threads = n_threads_sys;
	}

    parse(AES_KEY_LENGTH, argv[1], key);
    n_key_mask = parse_mask(argv[2], &key_mask);
    parse(BLOCK_SIZE, argv[3], plain_text);
    n_plaintext_mask = parse_mask(argv[4], &plaintext_mask);
    parse(BLOCK_SIZE, argv[5], cypher_text);
    printf("Key: ");
    print_hex(key, AES_KEY_LENGTH);
    printf("Plain text: ");
    print_hex(plain_text, BLOCK_SIZE);
    printf("Cypher text: ");
    print_hex(cypher_text, BLOCK_SIZE);
    printf("Key mask length: %ld\n", n_key_mask);
    printf("Plaintext mask length: %ld\n", n_plaintext_mask);
    printf("\n\n");
    search(n_key_mask, key_mask, n_plaintext_mask, plaintext_mask, key, plain_text, cypher_text);
	
}







