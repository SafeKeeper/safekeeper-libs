/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __STDINT_LIMITS
#define __STDINT_LIMITS
#endif
//for Linux
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif
#include <stdint.h>
#include <stdlib.h>

#include "se_memcpy.h"
#include "nrt_ukey_exchange.h"
#include "sgx_uae_service.h"
#include "sgx_ecp_types.h"
#include "se_lock.hpp"

#include "se_cdefs.h"
// Now sure what it does SGX_ACCESS_VERSION(ukey_exchange, 1)
// SGX_ACCESS_VERSION(nrt_uke, 1)

#ifndef ERROR_BREAK
#define ERROR_BREAK(x)  if(x){break;}
#endif
#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

sgx_status_t nrt_ra_get_quote(
    nrt_ra_context_t context,
    sgx_enclave_id_t eid,
    sgx_target_info_t *qe_target_info,
    const sgx_spid_t *spid,
    nrt_ecall_create_report_trusted_t p_create_report,
    nrt_ecall_get_quote_trusted_t p_get_quote,
    nrt_ra_msg_quote_t **pp_msg_quote,
    uint32_t *p_msg_quote_size)
{
    if(!p_get_quote || !p_msg_quote_size || !pp_msg_quote)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_report_t report;
    nrt_ra_msg_quote_t *p_msg_quote = NULL;

    memset(&report, 0, sizeof(report));

    {
        sgx_quote_nonce_t nonce;
        sgx_report_t qe_report;

        memset(&nonce, 0, sizeof(nonce));
        memset(&qe_report, 0, sizeof(qe_report));

        sgx_status_t status;
        ret = p_create_report(eid, &status, context, qe_target_info,
                              &report, &nonce);
        if(SGX_SUCCESS!=ret)
        {
            goto CLEANUP;
        }
        if(SGX_SUCCESS!=status)
        {
            ret = status;
            goto CLEANUP;
        }

        uint32_t quote_size = 0;
        // TODO SigRL size
        ret = sgx_calc_quote_size(NULL, 0,//p_msg2->sig_rl_size ? const_cast<uint8_t *>(p_msg2->sig_rl):NULL,
                                  &quote_size);
        if(SGX_SUCCESS!=ret)
        {
            goto CLEANUP;
        }

        //check integer overflow of quote_size
        if (UINT32_MAX - quote_size < sizeof(sgx_ra_msg3_t))
        {
            ret = SGX_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        uint32_t msg_quote_size = static_cast<uint32_t>(sizeof(nrt_ra_msg_quote_t)) + quote_size;
        p_msg_quote = (nrt_ra_msg_quote_t *)malloc(msg_quote_size);
        if(!p_msg_quote)
        {
            ret = SGX_ERROR_OUT_OF_MEMORY;
            goto CLEANUP;
        }
        memset(p_msg_quote, 0, msg_quote_size);

        // TODO decide unlinkable or linkable, fix SigRL
        ret = sgx_get_quote(&report,
                            SGX_LINKABLE_SIGNATURE,
                            spid,
                            &nonce,
                            NULL, //p_msg2->sig_rl_size ? const_cast<uint8_t *>(p_msg2->sig_rl):NULL,
                            0, //p_msg2->sig_rl_size,
                            &qe_report,
                            (sgx_quote_t *)p_msg_quote->quote,
                            quote_size);
        if(SGX_SUCCESS!=ret)
        {
            goto CLEANUP;
        }

        ret = p_get_quote(eid, &status, context, quote_size, &qe_report,
                          p_msg_quote, msg_quote_size);
        if(SGX_SUCCESS!=ret)
        {
            goto CLEANUP;
        }
        if(SGX_SUCCESS!=status)
        {
            ret = status;
            goto CLEANUP;
        }
        *pp_msg_quote = p_msg_quote;
        *p_msg_quote_size = msg_quote_size;
    }

CLEANUP:
    if(ret)
        SAFE_FREE(p_msg_quote);
    return ret;
}

sgx_status_t nrt_ra_set_gb(
    nrt_ra_context_t context,
    sgx_enclave_id_t eid,
    nrt_ecall_set_gb_trusted_t p_set_gb,
    const sgx_ec256_public_t *g_b)
{
    if(!g_b)
        return SGX_ERROR_INVALID_PARAMETER;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    sgx_status_t status;
    ret = p_set_gb(eid, &status, context, g_b);

    if(SGX_SUCCESS!=status)
        ret = status;

    return ret;
}

