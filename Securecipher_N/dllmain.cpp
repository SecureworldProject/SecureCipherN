
// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <malloc.h>
#include "context_cipher.h"

struct Cipher* cipher_data;

//Function prototypes
extern "C" _declspec(dllexport) int init(struct Cipher* cipher_data_param);
extern "C" _declspec(dllexport) int cipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key);
extern "C" _declspec(dllexport) int decipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key);

byte* get_message(size_t real_pos, struct KeyData* key) {
    byte message[20] = { 0 };
    //Preparar el message de 20 bytes por cada posicion, y los elementos por separado;
    byte pos_array[8];
    byte frn_array[4];
    byte key_array[8];
    int key_size = key->size;
    //Cojo la key y el frn primero el frn
    frn_array[0] = key->data[key_size - 3];//(frn >> 24) & 0xFF;
    frn_array[1] = key->data[key_size - 2];//(frn >> 16) & 0xFF;
    frn_array[2] = key->data[key_size - 1];//(frn >> 8) & 0xFF;
    frn_array[3] = key->data[key_size];//frn & 0xFF;
    //printf("%x %x %x %x\n", frn_array[0], frn_array[1], frn_array[2], frn_array[3]);
    //Si la key es mucho mas larga, hago xor para reducirla a 8, si la key es mas corta la repito
    int tam_key = key->size - 4;
    //si es menor, se hace bucle de 8, y se repite a partir de tam_key
    if (tam_key < 8) {
        for (int i = 0; i < 8; i++) {
            key_array[i] = key->data[i % tam_key];
        }
    }
    else {
        key_array[0] = key->data[0];
        key_array[1] = key->data[1];
        key_array[2] = key->data[2];
        key_array[3] = key->data[3];
        key_array[4] = key->data[4];
        key_array[5] = key->data[5];
        key_array[6] = key->data[6];
        key_array[7] = key->data[7];
        for (int i = 8; i < tam_key; i++) {
            int j = 0;
            key_array[j] = key_array[j] ^ key->data[i];
            j = (j + 1) % 8; 
        }
    }
    //Entro en el bucle del size
    pos_array[0] = (real_pos >> 56) & 0xFF;
    pos_array[1] = (real_pos >> 48) & 0xFF;
    pos_array[2] = (real_pos >> 40) & 0xFF;
    pos_array[3] = (real_pos >> 32) & 0xFF;
    pos_array[4] = (real_pos >> 24) & 0xFF;
    pos_array[5] = (real_pos >> 16) & 0xFF;
    pos_array[6] = (real_pos >> 8) & 0xFF;
    pos_array[7] = real_pos & 0xFF;
    int j = 0;
    //pos
    for (int i = 0; i < 8; i++) {
        message[j] = pos_array[i];
    }
    //frn
    for (int i = 0; i < 4; i++) {
        message[j] = frn_array[i];
    }
    //key
    for (int i = 0; i < 8; i++) {
        message[j] = key_array[i];
    }
    return message;
}

byte* lineal_transform(byte* message) {

    byte a[10] = { message[0], message[1], message[2], message[3], message[4] ,message[5], message[6], message[7], message[8], message[9] };
    byte b[10] = { message[10], message[11], message[12], message[13], message[14], message[15], message[16], message[17], message[18], message[19] };
    //printf("a = %x %x %x %x %x %x %x %x %x %x\n", a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
    //printf("b = %x %x %x %x %x %x %x %x %x %x\n", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]);
    //aux_a = a+b
    byte aux_a[11];
    //a = a + b
    byte overflow = 0x00;
    for (int i = 9; i > -1; i--) {
        aux_a[i + 1] = a[i] + b[i] + overflow;
        //printf("Resultado parcial: %x + %x (+%x)= %x\n", a[i], b[i], overflow, aux_a[i + 1]);
        if (aux_a[i + 1] > 0xF) {
            overflow = 0x01;
        }
        else {
            overflow = 0x00;
        }
    }
    if (overflow == 0x01) { aux_a[0] = 0x01; }
    else {
        aux_a[0] = aux_a[1];
        aux_a[1] = aux_a[2];
        aux_a[2] = aux_a[3];
        aux_a[3] = aux_a[4];
        aux_a[4] = aux_a[5];
        aux_a[5] = aux_a[6];
        aux_a[6] = aux_a[7];
        aux_a[7] = aux_a[8];
        aux_a[8] = aux_a[9];
        aux_a[9] = aux_a[10];
        aux_a[10] = aux_a[0];
    }
    //printf("resul aux_a = %x %x %x %x %x %x %x %x %x %x %x\n", aux_a[0], aux_a[1], aux_a[2], aux_a[3], aux_a[4], aux_a[5], aux_a[6], aux_a[7], aux_a[8], aux_a[9], aux_a[10]);

    //b = aux_a + 2b
    //2b
    byte aux_b[11];
    overflow = 0x00;
    for (int i = 9; i > -1; i--) {
        aux_b[i + 1] = b[i] + b[i] + overflow;
        //printf("Resultado parcial: %x + %x (+%x)= %x\n", b[i], b[i], overflow, aux_b[i + 1]);
        if (aux_b[i + 1] > 0xF) {
            overflow = 0x01;
        }
        else {
            overflow = 0x00;
        }
    }
    if (overflow == 0x01) { aux_b[0] = 0x01; }
    else {
        aux_b[0] = aux_b[1];
        aux_b[1] = aux_b[2];
        aux_b[2] = aux_b[3];
        aux_b[3] = aux_b[4];
        aux_b[4] = aux_b[5];
        aux_b[5] = aux_b[6];
        aux_b[6] = aux_b[7];
        aux_b[7] = aux_b[8];
        aux_b[8] = aux_b[9];
        aux_b[9] = aux_b[10];
        aux_b[10] = aux_b[0];
    }
    //PRINTf("resul aux_b = %x %x %x %x %x %x %x %x %x %x %x\n", aux_b[0], aux_b[1], aux_b[2], aux_b[3], aux_b[4], aux_b[5], aux_b[6], aux_b[7], aux_b[8], aux_b[9], aux_b[10]);

    //aux_bb = aux_a+aux_b
    byte aux_bb[12];
    overflow = 0x00;
    for (int i = 10; i > -1; i--) { //sumo dos arrays de 11
        aux_bb[i + 1] = aux_a[i] + aux_b[i] + overflow;
        //PRINTf("Resultado parcial: %x + %x (+%x)= %x\n", aux_a[i], aux_b[i], overflow, aux_bb[i + 1]);
        if (aux_bb[i + 1] > 0xF) {
            overflow = 0x01;
        }
        else {
            overflow = 0x00;
        }
    }
    if (overflow == 0x01) { aux_bb[0] = 0x01; }
    else {
        aux_bb[0] = aux_bb[1];
        aux_bb[1] = aux_bb[2];
        aux_bb[2] = aux_bb[3];
        aux_bb[3] = aux_bb[4];
        aux_bb[4] = aux_bb[5];
        aux_bb[5] = aux_bb[6];
        aux_bb[6] = aux_bb[7];
        aux_bb[7] = aux_bb[8];
        aux_bb[8] = aux_bb[9];
        aux_bb[9] = aux_bb[10];
        aux_bb[10] = aux_bb[11];
        aux_bb[11] = aux_bb[0];
    }
    //PRINTf("resul aux_bb= %x %x %x %x %x %x %x %x %x %x %x %x\n", aux_bb[0], aux_bb[1], aux_bb[2], aux_bb[3], aux_bb[4], aux_bb[5], aux_bb[6], aux_bb[7], aux_bb[8], aux_bb[9], aux_bb[10], aux_bb[11]);

    //actualizo el message
    //byte message[20];
    message[0] = aux_a[0];
    message[1] = aux_a[1];
    message[2] = aux_a[2];
    message[3] = aux_a[3];
    message[4] = aux_a[4];
    message[5] = aux_a[5];
    message[6] = aux_a[6];
    message[7] = aux_a[7];
    message[8] = aux_a[8];
    message[9] = aux_a[9];
    message[10] = aux_bb[0];
    message[11] = aux_bb[1];
    message[12] = aux_bb[2];
    message[13] = aux_bb[3];
    message[14] = aux_bb[4];
    message[15] = aux_bb[5];
    message[16] = aux_bb[6];
    message[17] = aux_bb[7];
    message[18] = aux_bb[8];
    message[19] = aux_bb[9];
    //PRINT("Message: %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx\n", message[0], message[1], message[2], message[3], message[4], message[5], message[6], message[7], message[8], message[9], message[10], message[11], message[12], message[13], message[14], message[15], message[16], message[17], message[18], message[19]);

    return message;
}

byte confusion(byte* message) {
    //confusion: message -> byte ciphered
    //convierto el mensaje en 4 numeros de 5 bytes
    byte variable_0[5] = { message[0], message[1], message[2], message[3], message[4] };
    byte variable_1[5] = { message[5], message[6], message[7], message[8], message[9] };
    byte variable_2[5] = { message[10], message[11], message[12], message[13], message[14] };
    byte variable_3[5] = { message[15], message[16], message[17], message[18], message[19] };
    //Ahora puedo sacar el valor entero, o puedo operar sobre cada byte

    uint64_t value_0 = ((uint64_t)variable_0[0] << 32) + ((uint64_t)variable_0[1] << 24) +
        ((uint64_t)variable_0[2] << 16) + ((uint64_t)variable_0[3] << 8) + (uint64_t)variable_0[4];
    //PRINT("\tValue_0 como int: %"PRIu64" y %"PRIx64"\n", value_0, value_0);
    uint64_t value_1 = ((uint64_t)variable_1[0] << 32) + ((uint64_t)variable_1[1] << 24) +
        ((uint64_t)variable_1[2] << 16) + ((uint64_t)variable_1[3] << 8) + (uint64_t)variable_1[4];
    //PRINT("\tValue_1 como int: %"PRIu64" y %"PRIx64"\n", value_0, value_1);
    uint64_t value_2 = ((uint64_t)variable_2[0] << 32) + ((uint64_t)variable_2[1] << 24) +
        ((uint64_t)variable_2[2] << 16) + ((uint64_t)variable_2[3] << 8) + (uint64_t)variable_2[4];
    //PRINT("\tValue_0 como int: %"PRIu64" y %"PRIx64"\n", value_2, value_2);
    uint64_t value_3 = ((uint64_t)variable_3[0] << 32) + ((uint64_t)variable_3[1] << 24) +
        ((uint64_t)variable_3[2] << 16) + ((uint64_t)variable_3[3] << 8) + (uint64_t)variable_3[4];
    //PRINT("\tValue_0 como int: %"PRIu64" y %"PRIx64"\n", value_3, value_3);


    //uint64_t resultado_xor = value_0 ^ value_1;
    uint64_t resultado = (0xFF) ^ (value_3) ^ (value_2) ^ (value_3 & value_1) ^ (value_2 & value_1) ^ (value_3 & value_2 & value_0) ^ (value_3 & value_1 & value_0) ^ (value_2 & value_1 & value_0) ^ (value_3 & value_2 & value_1 & value_0);
    //PRINT("\tResultado: %"PRIu64" y %"PRIx64" y entero %d\n", resultado, resultado, resultado % 256);
    resultado = resultado % 256;
    //PRINT("\tResultado final: %d\n", resultado);
    return resultado;
}

int init(struct Cipher* cipher_data_param) {
    cipher_data = cipher_data_param;
    printf("Initializing (%ws)\n", cipher_data->file_name);

    return 0;
}

int cipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key) { //offset es la posicion en el fichero, hacerlo bien que es la posicion que tengo que cifrar
    printf("Ciphering (%ws)\n", cipher_data->file_name);

    byte* message = (byte*)malloc(20*sizeof(byte));
    size_t buf_pos = 0; //posicion en el bufer, solo valida para escribir en el bufer, para cifrar se usa la posicion real en el fichero
    for (int real_pos = offset; real_pos < size + offset; real_pos++) {
        message = get_message(real_pos, key);
        //Hago la transformacion lineal y actualizo el message
        message = lineal_transform(message);
        //Confusion
        byte resultado = confusion(message);
        ((byte*)out_buf)[buf_pos] = (((byte*)in_buf)[buf_pos] + resultado);
        buf_pos++;
    }

    printf("Buffer ciphered");
    free(message);
    return 0;
}

int decipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key) {
    printf("Deciphering (%ws)\n", cipher_data->file_name);
    byte* message = (byte*)malloc(20 * sizeof(byte));
    size_t buf_pos = 0; //posicion en el bufer, solo valida para escribir en el bufer, para cifrar se usa la posicion real en el fichero
    for (int real_pos = offset; real_pos < size + offset; real_pos++) {
        message = get_message(real_pos, key);
        //Hago la transformacion lineal y actualizo el message
        message = lineal_transform(message);
        //Confusion
        byte resultado = confusion(message);
        ((byte*)out_buf)[buf_pos] = (((byte*)in_buf)[buf_pos] - resultado);
        buf_pos++;
    }

    printf("Buffer deciphered");
    free(message);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
