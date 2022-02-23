#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <memory.h>
#include "dhexchange.h"

static void _print_key(const char* name, const DH_KEY key) 
{
	int i;

	printf("%s=\t", name);
	for (i = 0; i< DH_KEY_LENGTH; i++)
	{
		printf("%02x", key[i]);
	}
	printf("\n");
}

static void create_key(const char* key_arr, const DH_KEY key) 
{
	int i;

	for (i = 0; i< DH_KEY_LENGTH; i++)
	{
	//	key[i] = key_arr[i]; //printf("%02x", key[i]);
	}
	printf("\n");
}

DH_KEY public_key = {0xcc, 0xb1, 0xcf, 0x31, 0x6e, 0xf3, 0xea, 0x88, 0x68, 0x48, 0x14, 0x72, 0xe8, 0x38, 0x5a, 0x7e};
DH_KEY private_key = {0x45, 0x45, 0x1f, 0xae, 0x9b, 0x3a, 0x9d, 0x5f, 0x46, 0x3c, 0xcb, 0x75, 0x63, 0x03, 0x55, 0x7c};

int main(void)
{
	DH_KEY bob_secret;

	time_t seed;
	time(&seed);
	srand((unsigned int)seed);

	/*Alice generate her private key and public key */
	//DH_generate_key_pair_a(alice_public, alice_private, private_key);

	/*Bob generate his private key and public key */
	//DH_generate_key_pair(bob_public, bob_private);

	/*Bob send his public key to Alice, Alice generate the secret key */
//	DH_generate_key_secret(alice_secret, alice_private, bob_public);

	/*Alice send her public key to Bob, Bob generate the secret key */
	//DH_generate_key_secret(bob_secret, bob_private, alice_public);

	DH_generate_key_secret(bob_secret, private_key, public_key);
	
	_print_key("privada", private_key);
	_print_key("publica", public_key);
	_print_key("bob_secret", bob_secret);
	return 0;
}
