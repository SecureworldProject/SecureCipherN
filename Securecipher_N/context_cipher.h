#pragma once
#ifndef CONTEXT_CIPHER_H
#define CONTEXT_CIPHER_H


/////  FILE INCLUDES  /////

#include <Windows.h>
#include <time.h>
#include <stdint.h>



#ifdef __cplusplus
extern "C" {
#endif	//__cplusplus


	/////  STRUCTS AND ENUMS  /////

	typedef unsigned char byte;

	struct Cipher {
		char* id;
		WCHAR* file_name;
		HINSTANCE lib_handle;
		int block_size;
		char* custom;
	};

	struct KeyData {
		byte* data;
		int size;
		time_t expires;
	};

#ifdef __cplusplus
}
#endif	//__cplusplus


#endif // !CONTEXT_CIPHER_H