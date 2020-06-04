#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <raylib.h>

#include "xtypes.h"
#include "blake2b.h"



/*
 * Data is processed in blocks which size has to be a power of 2
 */

#define BLOCK_SIZE_POW 12
#define BLOCK_SIZE (1 << BLOCK_SIZE_POW)










/*
 * This function converts '.mp3' file to easily processable and readable '.dat'
 * file. The resulting file has length of data (little-endian) in first 8 bytes
 * (as an unsigned integer), blake2b of data in next BLAKE2B_OUTBYTES, and plain
 * sample data till the end of file
 */

void
prepare_data_file(
	char const *path_in,
	char const *path_out
	)
{
	Wave wav = LoadWave(path_in);

	printf("loaded:\xa");
	printf(" * sampleCount == %u\xa", wav.sampleCount);
	printf(" * sampleRate == %u\xa", wav.sampleRate);
	printf(" * sampleSize == %u\xa", wav.sampleSize);
	printf(" * channels == %u\xa", wav.channels);
	printf(" * data == <0x%016lx>\xa", (size_t)wav.data);

	if (wav.sampleSize != 32)
	{
		fprintf(stderr, "wav.sampleSize: expected 32, got %u\xa", wav.sampleSize);
		UnloadWave(wav);
		return;
	}
	if (wav.channels != 2)
	{
		fprintf(stderr, "wav.channels: expected 2, got %u\xa", wav.channels);
		UnloadWave(wav);
		return;
	}

	u64 len = wav.sampleCount / 2;
	f32 *data = malloc(sizeof *data * len);
	if (!data)
		exit(EXIT_FAILURE);
	for (size_t i = 0;  i + 1 < wav.sampleCount;  i += 2)
	{
		f32 x = 0;
		x += ((f32*)wav.data)[i];
		x += ((f32*)wav.data)[i + 1];
		x /= 2;
		data[i / 2] = x;
	}
	UnloadWave(wav);

	byte hash[BLAKE2B_OUTBYTES];
	int res = blake2b(hash, BLAKE2B_OUTBYTES,
	                  data, sizeof *data * len,
	                  0, 0,
	                  0);
	if (res)
	{
		fprintf(stderr, "Failed to calculate blake2b(data), returned %d\xa", res);
		free(data);
		return;
	}

	FILE *f = fopen(path_out, "wb");
	if (!f)
	{
		fprintf(stderr, "Failed to open output file\xa");
		goto end_free;
	}

	if (fwrite(&len, 1, 8, f) < 8)
	{
		fprintf(stderr, "Failed to write length to output file\xa");
		goto end_close;
	}

	if (fwrite(hash, 1, BLAKE2B_OUTBYTES, f) < BLAKE2B_OUTBYTES)
	{
		fprintf(stderr, "Failed to write hash to output file\xa");
		goto end_close;
	}

	f32 *start = data;
	f32 *end = start + len;
	while (start < end)
	{
		size_t writeres = fwrite(start, sizeof *start, end - start, f);
		if (writeres <= 0)
		{
			fprintf(stderr, "Failed to write data to output file\xa");
			goto end_close;
		}
		start += writeres;
	}

end_close:
	fclose(f);
end_free:
	free(data);
	return;
}



/*
 * This function loads raw data from the .dat file (see the description of
 * `prepare_data_file` for file format) and checks the checksum.
 */

int
load_data(
	char *filename,
	f32 **arr_out,
	size_t *len_out
	)
{
	f32 *data;
	FILE *f;
	f = fopen(filename, "rb");
	if (!f)
	{
		return -1;
	}

	u64 len;
	if (fread(&len, 1, 8, f) < 8)
	{
		return -1;
	}

	byte hash_expected[BLAKE2B_OUTBYTES];
	byte hash_computed[BLAKE2B_OUTBYTES];
	if (fread(hash_expected, 1, BLAKE2B_OUTBYTES, f) < BLAKE2B_OUTBYTES)
	{
		return -1;
	}

	data = malloc(sizeof *data * len);
	if (!data)
		exit(EXIT_FAILURE);
	f32 *start = data;
	f32 *end = start + len;
	while (start < end)
	{
		size_t read = fread(start, 4, end - start, f);
		if (!read)
		{
			free(data);
			return -1;
		}

		start += read;
	}

	int res = blake2b(hash_computed, BLAKE2B_OUTBYTES,
	                  data, sizeof *data * len,
	                  0, 0,
	                  0);
	if (res)
	{
		free(data);
		return -1;
	}
	if (memcmp(hash_expected, hash_computed, BLAKE2B_OUTBYTES))
	{
		free(data);
		return -1;
	}

	*arr_out = data;
	*len_out = len;
	return 0;
}










f32
calculate_block(
	f32 *data,
	size_t len
	)
{
	f32 max = 0;
	f32 val;
	for (size_t i = 0;  i < len;  i++)
	for (size_t j = 0;  j < len;  j++)
	{
		val = data[i] * data[j] + data[i];
		if (fabsf(val) > max)
			max = val;
	}
	return max;
}



#define N_THREADS 2

struct manager_thread_param
{
	pthread_t thread_id;
	pthread_t workers[N_THREADS];
	f32 seq_percentage;
	f32 par_percentage;
	f32 *data;
	size_t n_blocks;
	f32 seq_res;
	f32 par_res;
	int done;
};

struct compute_thread_param
{
	f32 *data;
	size_t n_blocks;
	size_t next_block_to_compute;
	f32 *percentage;
	f32 accum;
	pthread_mutex_t mutex;
};



void *
compute_thread_proc(
	void *parg
	)
{
	struct compute_thread_param volatile *param = parg;
	f32 res = 0;
	while (1)
	{
		f32 *block;

		pthread_mutex_lock((pthread_mutex_t*)&param->mutex);

		param->accum += res;
		*param->percentage = ((f32)param->next_block_to_compute) / param->n_blocks;
		if (param->next_block_to_compute == param->n_blocks)
		{
			pthread_mutex_unlock((pthread_mutex_t*)&param->mutex);
			break;
		}
		block = param->data + param->next_block_to_compute * BLOCK_SIZE;
		param->next_block_to_compute++;

		pthread_mutex_unlock((pthread_mutex_t*)&param->mutex);

		res = calculate_block(block, BLOCK_SIZE);
		pthread_testcancel();
	}

	return 0;
}



void *
manager_thread_proc(
	void *parg
	)
{
	struct manager_thread_param *param = parg;
	struct compute_thread_param volatile compute_param;
	int res;

	memset((struct compute_thread_param *)&compute_param, 0, sizeof compute_param);
	compute_param.data = param->data;
	compute_param.n_blocks = param->n_blocks;
	compute_param.percentage = &param->par_percentage;

	res = pthread_mutex_init((pthread_mutex_t*)&compute_param.mutex, 0);
	if (res)
	{
		fprintf(stderr, "failed to create mutex, stop\xa");
		pthread_exit((void*)-1);
	}

	for (size_t i = 0;  i < N_THREADS;  i++)
	{
		res = pthread_create(&(param->workers[i]),
		                     0,
		                     compute_thread_proc,
		                     (struct compute_thread_param *)&compute_param);
		if (res)
		{
			fprintf(stderr, "failed to pthread_create(workers[%lu])\xa", i);
			param->workers[i] = 0;
		}
	}


	for (size_t i = 0;  i < param->n_blocks;  i++)
	{
		param->seq_res += calculate_block(param->data + i * BLOCK_SIZE, BLOCK_SIZE);
		param->seq_percentage = ((f32)i) / param->n_blocks;
		pthread_testcancel();
	}



	for (size_t i = 0;  i < N_THREADS;  i++)
	{
		res = pthread_join(param->workers[i], 0);
		if (res)
			fprintf(stderr, "failed to pthread_join(workers[%lu])\xa", i);
	}

	param->par_res = compute_param.accum;

	param->done = 1;
	return 0;
}










int
main(
	int argc,
	char **argv,
	char **env)
{
	MAKEUSED(argc);
	MAKEUSED(argv);
	MAKEUSED(env);

//	prepare_data_file("Rhapsody No. 2 in G Minor – Brahms.mp3", "data1.dat");
	f32 *data = 0;
	size_t len;
	int res = load_data("data1.dat", &data, &len);
	if (res)
	{
		fprintf(stderr, "Failed to read data (%d), stop.\xa", res);
		exit(EXIT_FAILURE);
	}

	printf("Data loaded successfully\xa");
	len /= BLOCK_SIZE;
	size_t n_blocks = len;
	len *= BLOCK_SIZE;



	const int screenWidth = 640;
	const int screenHeight = 360;

	InitWindow(screenWidth, screenHeight, "thread perf example");

	SetTargetFPS(60);



	struct manager_thread_param volatile manager_thread;
	memset((void *)&manager_thread, 0, sizeof manager_thread);

	manager_thread.data = data;
	manager_thread.n_blocks = n_blocks;

	res = pthread_create((pthread_t*)&manager_thread.thread_id,
	                     0,
	                     manager_thread_proc,
	                     (struct manager_thread_param *)&manager_thread);
	if (res)
	{
		fprintf(stderr, "failed to pthread_create(manager_thread), stop\xa");
		goto end;
	}



	while (!WindowShouldClose())
	{
		if (manager_thread.done)
			break;

		BeginDrawing();

		ClearBackground(RAYWHITE);

		DrawRectangle(319, 0, 2, 360, LIGHTGRAY);

		// Sequential stats:

		DrawText("Sequential", 10, 10, 40, BLACK);

		if (manager_thread.seq_percentage + 1E-4 < 1.0)
		{
			int startangle = 180 - (360 * manager_thread.seq_percentage);

			DrawCircle(160, 150,
			          64,
			          GRAY);
			DrawCircleSector((Vector2){160, 150},
			                 64,
			                 startangle, 180, 0, RED);
			char buf[0x10];
			snprintf(buf, 0x10, "%d%%", (int)(manager_thread.seq_percentage * 100));
			DrawText(buf, 145, 235, 20, DARKGRAY);
		}
		else
		{
			DrawCircle(160, 150,
			          64,
			          LIME);
			DrawText("DONE", 135, 235, 20, DARKGRAY);
		}

		// Threaded stats:

		DrawText("Threaded", 320 + 10, 10, 40, BLACK);

		if (manager_thread.par_percentage + 1E-4 < 1.0)
		{
			int startangle = 180 - (360 * manager_thread.par_percentage);

			DrawCircle(320 + 160, 150,
			          64,
			          GRAY);
			DrawCircleSector((Vector2){320 + 160, 150},
			                 64,
			                 startangle, 180, 0, RED);
			char buf[0x10];
			snprintf(buf, 0x10, "%d%%", (int)(manager_thread.par_percentage * 100));
			DrawText(buf, 320 + 145, 235, 20, DARKGRAY);
		}
		else
		{
			DrawCircle(320 + 160, 150,
			          64,
			          LIME);
			DrawText("DONE", 320 + 135, 235, 20, DARKGRAY);
		}

		EndDrawing();
	}

	if (!manager_thread.done)
	{
		// The window was closed before compute threads had a chance to
		// complete their work
		pthread_cancel(manager_thread.thread_id);
		for (size_t i = 0;  i < N_THREADS;  i++)
		{
			if (manager_thread.workers[i])
				pthread_cancel(manager_thread.workers[i]);
		}

		pthread_join(manager_thread.thread_id, 0);

		for (size_t i = 0;  i < N_THREADS;  i++)
		{
			if (manager_thread.workers[i])
				pthread_join(manager_thread.workers[i], 0);
		}

		goto end;
	}

	res = pthread_join(manager_thread.thread_id, 0);
	if (res)
	{
		fprintf(stderr, "failed to pthread_join(manager_thread.thread_id, 0), stop\xa");
		goto end;
	}

	char finalmsg[0x100];
	snprintf(finalmsg, 0x100, "Final result:\xa * seq : %f,\xa * par : %f",
		manager_thread.seq_res,
		manager_thread.par_res);

	int results_are_equal =
		(fabsf(manager_thread.seq_res - manager_thread.par_res) - 1E-9) < 0;

	while (!WindowShouldClose())
	{
		BeginDrawing();

		ClearBackground(RAYWHITE);

		if (results_are_equal)
			DrawText(finalmsg, 10, 10, 40, BLACK);
		else
			DrawText(finalmsg, 10, 10, 40, RED);

		EndDrawing();
	}

end:
	free(data);
	CloseWindow();

	return 0;
}
