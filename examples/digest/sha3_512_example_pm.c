/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // Required for gettimeofday

#include "alcp/digest.h"

#define DIGEST_SIZE 64

static alc_digest_handle_t s_dg_handle;

static alc_error_t
create_demo_session(void)
{
    alc_error_t err;

    Uint64 size         = alcp_digest_context_size();
    s_dg_handle.context = malloc(size);

    if (!s_dg_handle.context) {
        return ALC_ERROR_NO_MEMORY;
    }

    err = alcp_digest_request(ALC_SHA3_512, &s_dg_handle);

    if (alcp_is_error(err)) {
        return err;
    }

    err = alcp_digest_init(&s_dg_handle);

    if (alcp_is_error(err)) {
        return err;
    }

    return err;
}

static alc_error_t
hash_demo(const Uint8* src,
          Uint64       src_size,
          Uint8*       output,
          Uint64       out_size,
          Uint64       num_chunks)
{
    clock_t start_time, end_time;
    double cpu_time_used;
    start_time = clock(); // Record the start time
    printf("src_size (bytes): %ld\n",src_size);

    alc_error_t err;
    // divide the input size into multiple chunks
    const Uint64 buf_size      = src_size / num_chunks;
    const Uint64 last_buf_size = src_size % num_chunks;
    const Uint8* p             = src;

    while (num_chunks-- > 0) {
        err = alcp_digest_update(&s_dg_handle, p, buf_size);
        if (alcp_is_error(err)) {
            printf("Unable to compute SHA3 hash\n");
            goto out;
        }
        p += buf_size;
    }

    if (last_buf_size) {
        err = alcp_digest_update(&s_dg_handle, p, last_buf_size);
        if (alcp_is_error(err)) {
            printf("Unable to compute SHA3 hash\n");
            goto out;
        }
    }

    err = alcp_digest_finalize(&s_dg_handle, output, out_size);

    if (alcp_is_error(err)) {
        printf("Unable to copy digest\n");
    }

out:
    alcp_digest_finish(&s_dg_handle);
    free(s_dg_handle.context);

    end_time = clock(); // Record the end time
    cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Execution time: %f seconds\n", cpu_time_used);

    return err;
}

/*
int
main(int argc, char const* argv[])
{

    uint64_t txt_size = 1024; // in byte
    if (argc > 1) {
        txt_size = atoi(argv[1]);
        printf("set text size to %ld\n",txt_size);
    }
    Uint8* sample_input = (Uint8*) malloc(txt_size+1);

    char j = '0';
    for(int i = 0; i < txt_size; i++, j++) {
        if (j > '9') j = '0';
        sample_input[i] = j;
    }
    sample_input[txt_size] = '\0';


    Uint64 num_chunks = 1;
    if (argc > 2) {
        num_chunks = atoi(argv[2]);
        printf("set num_chunks to %ld\n",num_chunks);
    }


    Uint8 sample_output[DIGEST_SIZE] = { 0 };

    for (int i = 0; i < 2;i++) {

        alc_error_t err = create_demo_session();
        if (alcp_is_error(err)) {
            return -1;
        }
        err = hash_demo(sample_input,
                        strlen((const char*)sample_input),
                        sample_output,
                        sizeof(sample_output),
                        num_chunks);
        if (alcp_is_error(err)) {
            return -1;
        }
    }
    return 0;
}
*/
int
main(int argc, char const* argv[])
{

    uint64_t txt_size = 895; // last chunk must have room for msg size
    Uint64 num_chunks = 1;
    if (argc > 1) {
        num_chunks = atoi(argv[1]);
        printf("set num_chunks to %ld\n",num_chunks);
        txt_size += (num_chunks-1)* 1024;
        printf("set text size to %ld\n",txt_size);
    }
    Uint8* sample_input = (Uint8*) malloc(txt_size+1);

    char j = '0';
    for(int i = 0; i < txt_size; i++, j++) {
        if (j > '9') j = '0';
        sample_input[i] = j;
    }
    sample_input[txt_size] = '\0';


    Uint8 sample_output[DIGEST_SIZE] = { 0 };

    for (int i = 0; i < 2;i++) {

        alc_error_t err = create_demo_session();
        if (alcp_is_error(err)) {
            return -1;
        }
        err = hash_demo(sample_input,
                        strlen((const char*)sample_input),
                        sample_output,
                        sizeof(sample_output),
                        num_chunks);
        if (alcp_is_error(err)) {
            return -1;
        }
    }
    return 0;
}
