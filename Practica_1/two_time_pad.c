#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 14

void contar_espacios(tam, espacio, c_x)
unsigned char *tam;
unsigned char **espacio;
unsigned char **c_x;
{
	int i, j, k;
	int min;
	unsigned char xor;
	// Tratando mensajes para buscar espacios
	// c0 = k (+) m0
	// c1 = k (+) m1
	// c0 (+) c1 = m0 (+) m1
	// De aquí se tienen que guardar las posiciones de las letras minusculas (valor ascii) y sumar esta detección
	
	for(i = 0; i < N; i++)
	for(j = i+1; j < N; j++)
	{
		// Obteniendo longitud mínima
		if(tam[i] <= tam[j]) 	min = tam[i]; 
		else 			min = tam[j];

		for(k = 0; k < min; k++)
		{
			xor = c_x[i][k] ^ c_x[j][k];

			// Resultado del xor está dentro del rango ASCII? Contador en ambos
			if( (xor >= 'a' && xor <= 'z') || (xor >= 'A' && xor <= 'Z'))
			{
				espacio[i][k] += 1;
				espacio[j][k] += 1;
			}	
		}
	}

}


int main(int argc, char *argv[]){

	if(argc != 2)
	{
		fprintf(stderr, "Uso: %s <Número de espacios como criterio>\n", argv[0]);
		exit(-1);
	}

	int criterio = atoi(argv[1]);
	int i, j, k;
	int min;	// Longitud minima posible
	unsigned char *tam;
	unsigned char xor;
	unsigned char *conv;
	//int **c_int;
	
	// mensaje cifrado en string
	unsigned char *c[] = {	"1a1617451a411517490b061b0f08535404044e17450c1c45326222420a00340006544816170b54030b55020d530046",
				"184f184f0a081a000016071a00010017090b00100416010054530e060c52301b0c000a131304430e0a0640",
				"09001a5248041b04490a4f060b07550601115953150c010007000604134f2b4f01481a0417115348",
				"7926114506151f1159461b1d0b025454010850120617014542104b08104c35061a4e48201b00520f0c1400170e",
				"0c3c5547071713174e0b0a1b1a445018090b5353110c5216044505015904685a5542010d1a0c4f084f1a0044430d0a005200000007171d54124b",
				"1a001c4e480c1f0b490808551e1645070d0b5400450252071d474b020b4f2e1b1d00010f560659040a070d1649190d4b",
				"0d0710003d32560c5346211a4e550000091747161143140a06001f040b473c1b1044480002114105040640",
				"1c02054c0718130000080a12020d47110606455306021c45174f06150b4f34060645480f131157091d1e4e1745171d1749071c4d",
				"103b55530d02031749121655070a541104094914000d1100544918450c4e3d0a07551c081a0c5a030b5b",
				"120a1050010f1145410a03551d0b46001f0452164516020115540e0159492a4f14441e0805004448",
				"793b024f48151f0845461f140a444907480b4f074510170601520e4959552a0a5541480f1312000d0a0c4e0141170045541a08065c",
				"163b55530d020317491216551e1645070d0b54004502520b11574b161c54790013000b0917094c0301120b170e",
				"100021000c04000c43031c550d054e54010b43010002010054530e060c52301b0c001e141a0b45140e17070849000100535d",
				"793b1d451a04560c53460e550d1d42111a4553160616000c00594b161249350306001b0919175407081040"};
	unsigned char **c_x; // Mensaje cifrado en hexadecimal
	unsigned char **m; // Mensaje descifrado
	unsigned char **espacio;
	unsigned char *key;
	unsigned char *key_r = "You have found the secret key ";
	int max = 0;
	int key_length = strlen(key_r);

	//
	// Inicializando variables
	//
	
	conv = malloc(sizeof(char) * 2);
	m = malloc(sizeof(char *) * N);
	tam = malloc(sizeof(char) * N);
	c_x = malloc(sizeof(char *) * N);
	espacio = malloc(sizeof(char *) * N);

	for(i = 0; i < N; i++)
	{
		tam[i] = strlen(c[i])/2;
		if(max < tam[i]) 
			max = tam[i];
		c_x[i] = malloc(tam[i] * sizeof(char));
		m[i] = malloc(tam[i] * sizeof(char));
		espacio[i] = malloc(tam[i] * sizeof(char));
	}
	
	key = malloc(max * sizeof(char));

	for(i = 0; i < max; i++) 
		key[i] = '-';


	// Traduciendo mensaje de hexadecimal en string a unsigned char
	for(i = 0; i < N; i++)
	for(j = 0; j < tam[i]; j++)
	{
		conv[0] = c[i][j*2 + 0];
		conv[1] = c[i][j*2 + 1];
		espacio[i][j] = 0;
		m[i][j] = '-';

		c_x[i][j] = (unsigned char)strtol(conv, NULL, 16);
	}
	

	// Asumiendo que los mensajes están codificados en ASCII
	contar_espacios(tam, espacio, c_x);
	

	// Mirando si supera el criterio de espacios para descifrarlos
	for(i = 0; i < N; i++)
	for(j = 0; j < tam[i]; j++)
		if(espacio[i][j] > criterio)
		{
			// Poniendo como espacio al mensaje
			m[i][j] = ' ';

			// Consiguiendo la letra en los otros mensajes
			for(k = 0; k < N; k++)
			{
				// Si está en rango y no es el mismo mensaje cifrado
				if(k != i && j < tam[k])
					m[k][j] = c_x[i][j] ^ c_x[k][j] ^ 0x20;

				// Descifrando parte de la Key
				// mi[j] = ci[j] (+) k[j]
				// mi (+) ci[j] = k[j]
				key[j] = m[i][j] ^ c_x[i][j];
			}
		}
	

	// Mostrando resultados
	printf("Mensajes obtenidos: \n");
	for(i = 0; i < N; i++)
	{
		printf("%s\n",m[i]);	
	}
	printf("Key obtenida: %s\n",key);
	printf("\n-----------\n");
	printf("Key real: %s\n", key_r);
	printf("Mensajes descifrados:\n");
	for(i = 0; i < N; i++)
	{
		for(j = 0; j < tam[i]; j++)
		{
			printf("%c", c_x[i][j] ^ key_r[j%key_length]);
		}
		printf("\n");
	}
}
