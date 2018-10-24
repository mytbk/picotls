/*
 * Copyright (c) 2018 Fastly
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "brotli/decode.h"
#include "picotls/decompress_certificate.h"

static inline int decompress_certificate(ptls_decompress_certificate_t *self, ptls_t *tls, uint16_t algorithm, ptls_iovec_t output,
                                         ptls_iovec_t input)
{
    if (algorithm != PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI)
        goto Fail;

    size_t decoded_size = output.len;
    if (BrotliDecoderDecompress(input.len, input.base, &decoded_size, output.base) != BROTLI_DECODER_RESULT_SUCCESS)
        goto Fail;

    if (decoded_size != output.len)
        goto Fail;

    return 0;
Fail:
    return PTLS_ALERT_BAD_CERTIFICATE;
}

static const uint16_t algorithms[] = {PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI, UINT16_MAX};

ptls_decompress_certificate_t ptls_decompress_certificate = {algorithms, decompress_certificate};
