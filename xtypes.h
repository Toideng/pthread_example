#ifndef XTYPES_H
#define XTYPES_H

#include <stdint.h>
#include <stddef.h> // for size_t, ssize_t



// Use this template to disable unnecessary warnings

#pragma GCC diagnostic ignored "-Wpedantic"
// ...
#pragma GCC diagnostic pop



#define MAKEUSED(x) ((void)(x))
#define MIN(a, b) (((a)<(b))?(a):(b))
#define MAX(a, b) (((a)>(b))?(a):(b))

#ifndef _in_
#define _in_
#endif
#ifndef _out_
#define _out_
#endif
#ifndef _inout_
#define _inout_
#endif

#define HEXADIGITSTR      "0123456789abcdef"
#define HEXADIGITSTRLOWER HEXADIGITSTR
#define HEXADIGITSTRUPPER "0123456789ABCDEF"

// Seconds since 1970-01-01 00:00z to 2000-01-01 00:00z
#define NEWEPOCH ((i64)946684800)

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef u8 byte;
typedef i32 bool32;

typedef float  f32;
typedef double f64;

typedef int unsigned uint;



// Typedef on struct is used to ensure CXX-compatibility

typedef struct buffer
{
	union
	{
		void* p;
		byte* data;
		char* text;
	};
	size_t len;
	size_t cap;
} buffer;


typedef struct fixedbuffer
{
	union
	{
		void* p;
		byte* data;
		char* text;
	};
	size_t len;
} fixedbuffer;



#endif /* XTYPES_H */
