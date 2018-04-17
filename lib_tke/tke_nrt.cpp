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

#include <stdint.h>
#include <vector>
#include "nrt_tke.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "ecp_interface.h"
#include "util.h"
#include "string.h"
#include "stdlib.h"
#include "sgx_spinlock.h"
#include "nrt_tke_t.h"
#include "se_cdefs.h"

// Add a version to tkey_exchange.
// SGX_ACCESS_VERSION(tkey_exchange, 1)

#define ERROR_BREAK(sgx_status)  if(SGX_SUCCESS!=sgx_status){break;}
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}

#pragma pack(push, 1)

// any call to sgx_ra_init will reset the input pubkey related ra_db_item_t.ra_state to ra_inited
// only sgx_ra_get_ga can change ra_inited to ra_get_gaed
// only nrt_ra_create_report_trusted can change ra_get_gaed to ra_report_created
// nrt_ra_get_quote_trusted and nrt_ra_get_keys will check ra_state whether to be ra_report_created

typedef enum _ra_state
{
    ra_inited= 0,
    ra_get_gaed,
    ra_report_created,
    ra_keys_generated
} ra_state;

typedef struct _ra_db_item_t
{
    sgx_ec256_public_t          g_a;
    sgx_ec256_public_t          g_b;
    sgx_ec256_private_t         a;
    sgx_ps_sec_prop_desc_t      ps_sec_prop;
    sgx_ec_key_128bit_t         mk_key;
    sgx_ec_key_128bit_t         sk_key;
    sgx_quote_nonce_t           quote_nonce; //to verify quote report data
    sgx_target_info_t           qe_target;   //to verify quote report
    ra_state                    state;
    sgx_spinlock_t              item_lock;
    uintptr_t                   derive_key_cb;
} ra_db_item_t;

#pragma pack(pop)

static std::vector<ra_db_item_t*> g_ra_db;
static sgx_spinlock_t g_ra_db_lock = SGX_SPINLOCK_INITIALIZER;
static uintptr_t g_kdf_cookie = 0;
#define ENC_KDF_POINTER(x)  (uintptr_t)(x) ^ g_kdf_cookie
#define DEC_KDF_POINTER(x)  (nrt_ra_derive_secret_keys_t)((x) ^ g_kdf_cookie)

extern "C" sgx_status_t nrt_ra_get_ga(
    nrt_ra_context_t context,
    sgx_ec256_public_t *g_a)
{
    sgx_status_t se_ret;
    ra_db_item_t* item = NULL;

    if(g_ra_db.size() <= context || !g_a)
        return SGX_ERROR_INVALID_PARAMETER;

    item = g_ra_db[context];

    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_ec256_public_t pub_key;
    sgx_ec256_private_t priv_key;

    memset(&pub_key, 0, sizeof(pub_key));
    memset(&priv_key, 0, sizeof(priv_key));

    sgx_spin_lock(&item->item_lock);
    do
    {
        // we allow subsequent calls to get_ga
        if (item->state == ra_report_created ||
            item->state == ra_keys_generated)
        {
            se_ret = SGX_SUCCESS;
            break;
        }
        //sgx_ra_init must have been called
        if (item->state != ra_inited)
        {
            se_ret = SGX_ERROR_INVALID_STATE;
            break;
        }
        // ecc_state should be closed when exit.
        se_ret = sgx_ecc256_open_context(&ecc_state);
        if (SGX_SUCCESS != se_ret)
        {
            if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
                se_ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        se_ret = sgx_ecc256_create_key_pair(&priv_key, &pub_key, ecc_state);
        if (SGX_SUCCESS != se_ret)
        {
            if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
                se_ret = SGX_ERROR_UNEXPECTED;
            break;
        }
        memcpy(&item->a, &priv_key, sizeof(item->a));
        memcpy(&item->g_a, &pub_key, sizeof(item->g_a));
        item->state = ra_get_gaed;
        //clear local private key to defense in depth
        memset_s(&priv_key, sizeof(priv_key), 0, sizeof(sgx_ec256_private_t));
    } while(0);
    sgx_spin_unlock(&item->item_lock);
    if(ecc_state != NULL)
        sgx_ecc256_close_context(ecc_state);
    if(se_ret == SGX_SUCCESS)
        memcpy(g_a, &item->g_a, sizeof(item->g_a));
    return se_ret;
}

extern "C" sgx_status_t nrt_ra_create_report(
    nrt_ra_context_t context,
    const sgx_target_info_t *p_qe_target,
    sgx_report_t *p_report,
    sgx_quote_nonce_t* p_nonce)
{
    ra_db_item_t* item = NULL;
    sgx_status_t se_ret = SGX_ERROR_UNEXPECTED;
    //p_qe_target[in] p_report[out] p_nonce[out] in EDL file
    if(g_ra_db.size() <= context
       || !p_qe_target
       || !p_report
       || !p_nonce)
        return SGX_ERROR_INVALID_PARAMETER;

    item = g_ra_db[context];

    sgx_ec256_private_t a;
    memset(&a, 0, sizeof(a));
    sgx_spin_lock(&item->item_lock);

    // sgx_ra_get_ga must have been called
    // we allow multiple calls to generate report
    if (item->state == ra_inited)
    {
        sgx_spin_unlock(&item->item_lock);
        return SGX_ERROR_INVALID_STATE;
    }
    memcpy(&a, &item->a, sizeof(a));

    sgx_ecc_state_handle_t ecc_state = NULL;

    // ecc_state need to be freed when exit.
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != se_ret)
    {
        if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
            se_ret = SGX_ERROR_UNEXPECTED;
        sgx_spin_unlock(&item->item_lock);
        return se_ret;
    }

    // create a nonce
        do {
    se_ret = sgx_read_rand((uint8_t*)p_nonce, sizeof(sgx_quote_nonce_t));
    if (SGX_SUCCESS != se_ret)
    {
        if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
            se_ret = SGX_ERROR_UNEXPECTED;
        break;
    }

    memcpy(&item->qe_target, p_qe_target, sizeof(sgx_target_info_t));
    memcpy(&item->quote_nonce, p_nonce, sizeof(sgx_quote_nonce_t));
    sgx_report_data_t report_data = {{0}};
    // se_static_assert(sizeof(sgx_report_data_t)>=sizeof(sgx_sha256_hash_t));
    // REPORTDATA = H
    // report_data is 512bits, H is 256bits.
    // The hash could be is the lower 256 bits of report data
    // while the higher 256 bits are all zeros.
    // ec256 public key is 512 bits, so takes whole report data.
    // each coordinate of ec256 public is in little endian
    // put it in the quote in big endian
    for( int i = 0; i < SGX_ECP256_KEY_SIZE; i++ ) {
        report_data.d[i] = item->g_a.gx[SGX_ECP256_KEY_SIZE-1 - i];
        report_data.d[i + SGX_ECP256_KEY_SIZE] = item->g_a.gy[SGX_ECP256_KEY_SIZE-1 - i];
    }
    se_ret = sgx_create_report(p_qe_target, &report_data, p_report);
    if (SGX_SUCCESS != se_ret)
    {
        if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
            se_ret = SGX_ERROR_UNEXPECTED;
        break;
    }
    item->state = ra_report_created;
        } while(0);

    sgx_spin_unlock(&item->item_lock);

    sgx_ecc256_close_context(ecc_state);
    memset_s(&a, sizeof(sgx_ec256_private_t), 0, sizeof(sgx_ec256_private_t));
    return se_ret;
}


/* the caller is supposed to fill the quote field in emp_msg3 before calling
 * this function.*/
extern "C" sgx_status_t nrt_ra_get_quote_trusted(
    nrt_ra_context_t context,
    uint32_t quote_size,
    sgx_report_t* qe_report,
    nrt_ra_msg_quote_t *emp_msg_quote,    //(mac||g_a||ps_sec_prop||quote)
    uint32_t msg_quote_size)
{
    if(g_ra_db.size() <= context || !quote_size || !qe_report || !emp_msg_quote)
        return SGX_ERROR_INVALID_PARAMETER;

    ra_db_item_t* item = g_ra_db[context];

    //check integer overflow of msg_quote_size and quote_size
    if (UINTPTR_MAX - reinterpret_cast<uintptr_t>(emp_msg_quote) < msg_quote_size ||
        UINT32_MAX - quote_size < sizeof(nrt_ra_msg_quote_t) ||
        sizeof(nrt_ra_msg_quote_t) + quote_size != msg_quote_size)
        return SGX_ERROR_INVALID_PARAMETER;

    if (!sgx_is_outside_enclave(emp_msg_quote, msg_quote_size))
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t se_ret = SGX_ERROR_UNEXPECTED;

    //verify qe report
    se_ret = sgx_verify_report(qe_report);
    if(se_ret != SGX_SUCCESS)
    {
        if (SGX_ERROR_MAC_MISMATCH != se_ret &&
            SGX_ERROR_OUT_OF_MEMORY != se_ret)
            se_ret = SGX_ERROR_UNEXPECTED;
        return se_ret;
    }

    sgx_spin_lock(&item->item_lock);
    //sgx_ra_create_report must have been called
    // but we allow multiple calls
    if (item->state != ra_report_created &&
        item->state != ra_keys_generated)
    {
        sgx_spin_unlock(&item->item_lock);
        return SGX_ERROR_INVALID_STATE;
    }
    //verify qe_report attributes and mr_enclave same as quoting enclave
    if( memcmp( &qe_report->body.attributes, &item->qe_target.attributes, sizeof(sgx_attributes_t)) ||
        memcmp( &qe_report->body.mr_enclave, &item->qe_target.mr_enclave, sizeof(sgx_measurement_t)) )
    {
        sgx_spin_unlock(&item->item_lock);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    nrt_ra_msg_quote_t msg_quote_except_quote_in;

    memcpy(&msg_quote_except_quote_in.g_a, &item->g_a, sizeof(msg_quote_except_quote_in.g_a));
    memcpy(&msg_quote_except_quote_in.ps_sec_prop, &item->ps_sec_prop,
        sizeof(msg_quote_except_quote_in.ps_sec_prop));
    sgx_spin_unlock(&item->item_lock);

    sgx_sha_state_handle_t sha_handle = NULL;

    //SHA256(NONCE || emp_quote)
    sgx_sha256_hash_t hash = {0};
    se_ret = sgx_sha256_init(&sha_handle);
    if (SGX_SUCCESS != se_ret)
    {
        if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
            se_ret = SGX_ERROR_UNEXPECTED;
        return se_ret;
    }
    if (NULL == sha_handle)
        {
            return SGX_ERROR_UNEXPECTED;
        }
    do
    {
        se_ret = sgx_sha256_update((uint8_t *)&item->quote_nonce,
            sizeof(item->quote_nonce),
            sha_handle);
        if (SGX_SUCCESS != se_ret)
        {
            if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
                se_ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        // cmac   M := ga || PS_SEC_PROP_DESC(all zero if unused) ||emp_quote
        // Used to be here, but no keys, so drop it

        // sha256 and cmac quote
        uint8_t quote_piece[32];
        const uint8_t* emp_quote_piecemeal = emp_msg_quote->quote;
        uint32_t quote_piece_size = static_cast<uint32_t>(sizeof(quote_piece));

        while (emp_quote_piecemeal < emp_msg_quote->quote + quote_size)
        {
            //calculate size of one piece, the size of them are sizeof(quote_piece) except for the last one.
            if (static_cast<uint32_t>(emp_msg_quote->quote + quote_size - emp_quote_piecemeal) < quote_piece_size)
                quote_piece_size = static_cast<uint32_t>(emp_msg_quote->quote - emp_quote_piecemeal) + quote_size ;
            memcpy(quote_piece, emp_quote_piecemeal, quote_piece_size);
            se_ret = sgx_sha256_update(quote_piece,
                                    quote_piece_size,
                                    sha_handle);
           if (SGX_SUCCESS != se_ret)
           {
               if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
                   se_ret = SGX_ERROR_UNEXPECTED;
              break;
           }
           emp_quote_piecemeal += sizeof(quote_piece);
        }
        ERROR_BREAK(se_ret);

        //get sha256 hash value
        se_ret = sgx_sha256_get_hash(sha_handle, &hash);
        if (SGX_SUCCESS != se_ret)
        {
            if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
                se_ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        //get cmac value

        //verify qe_report->body.report_data == SHA256(NONCE || emp_quote)
        if(0 != memcmp(&qe_report->body.report_data, &hash, sizeof(hash)))
        {
            se_ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

        //memcpy(&msg_quote_except_quote_in.mac, mac, sizeof(mac));
        memcpy(emp_msg_quote, &msg_quote_except_quote_in, offsetof(nrt_ra_msg_quote_t, quote));
        se_ret = SGX_SUCCESS;
    } while(0);
    (void)sgx_sha256_close(sha_handle);
    return se_ret;
}

static sgx_status_t nrt_ra_fill_keys( ra_db_item_t* item ) {
    sgx_status_t se_ret = SGX_ERROR_UNEXPECTED;
    sgx_ec256_private_t a;
    sgx_ec256_dh_shared_t dh_key;
    sgx_ec_key_128bit_t skey = {0};
    nrt_ra_derive_secret_keys_t ra_key_cb = NULL;
    sgx_ecc_state_handle_t ecc_state = NULL;

    memcpy(&a, &item->a, sizeof(a));
    memset(&dh_key, 0, sizeof(dh_key));

    // ecc_state need to be freed when exit.
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != se_ret)
    {
        if(SGX_ERROR_OUT_OF_MEMORY != se_ret)
            se_ret = SGX_ERROR_UNEXPECTED;
        return se_ret;
    }

    se_ret = sgx_ecc256_compute_shared_dhkey(&a,
        &(item->g_b),
        &dh_key, ecc_state);
    if(SGX_SUCCESS != se_ret)
    {
        if (SGX_ERROR_OUT_OF_MEMORY != se_ret)
            se_ret = SGX_ERROR_UNEXPECTED;
        sgx_ecc256_close_context(ecc_state);
        return se_ret;
    }

    ra_key_cb = DEC_KDF_POINTER(item->derive_key_cb);
    if(NULL != ra_key_cb)
    {
        se_ret = ra_key_cb(&dh_key,
                           0,
                           NULL,
                           &skey,
                           NULL,
                           NULL);
        if (SGX_SUCCESS != se_ret)
        {
            if( SGX_ERROR_OUT_OF_MEMORY != se_ret &&
                SGX_ERROR_INVALID_PARAMETER != se_ret &&
                SGX_ERROR_KDF_MISMATCH != se_ret)
                se_ret = SGX_ERROR_UNEXPECTED;
            sgx_ecc256_close_context(ecc_state);
            return se_ret;
        }
    }

    memcpy(&item->sk_key, skey, sizeof(item->sk_key));

    memset_s(&dh_key, sizeof(dh_key), 0, sizeof(dh_key));
    memset_s(&a, sizeof(sgx_ec256_private_t), 0, sizeof(sgx_ec256_private_t));
    memset_s(skey, sizeof(sgx_ec_key_128bit_t), 0, sizeof(sgx_ec_key_128bit_t));
    sgx_ecc256_close_context(ecc_state);

    return se_ret;
}

extern "C" sgx_status_t nrt_ra_set_gb_trusted(
    nrt_ra_context_t context,
    const sgx_ec256_public_t *g_b)
{
    sgx_status_t se_ret = SGX_SUCCESS;
    if(g_ra_db.size() <= context || !g_b)
        return SGX_ERROR_INVALID_PARAMETER;
    ra_db_item_t* item = g_ra_db[context];

    sgx_spin_lock(&item->item_lock);
    do
    {
        //nrt_create_report must have been called
        // we allow multiple calls but this should be
        // bound to get_keys, otherwise we have got
        // problem if something else calls set_gb
        // TODO combine set_gb with get_keys
        if (item->state != ra_report_created && item->state != ra_keys_generated)
        {
            se_ret = SGX_ERROR_INVALID_STATE;
            break;
        }
        memcpy(&item->g_b, g_b, sizeof(item->g_b));
        se_ret = nrt_ra_fill_keys(item);
        if (SGX_SUCCESS != se_ret)
            break;

        item->state = ra_keys_generated;
    } while(0);
    sgx_spin_unlock(&item->item_lock);
    return se_ret;
}

// TKE interface for enclaves
sgx_status_t nrt_ra_init_ex(
    int b_pse,
    nrt_ra_derive_secret_keys_t derive_key_cb,
    nrt_ra_context_t *p_context)
{
    sgx_status_t ret = SGX_SUCCESS;

    // initialize g_kdf_cookie for the first time sgx_ra_init_ex is called.
    if (unlikely(g_kdf_cookie == 0))
    {
        uintptr_t rand = 0;
        do
        {
            if (SGX_SUCCESS != sgx_read_rand((unsigned char *)&rand, sizeof(rand)))
            {
                return SGX_ERROR_UNEXPECTED;
            }
        } while (rand == 0);

        sgx_spin_lock(&g_ra_db_lock);
        if (g_kdf_cookie == 0)
        {
            g_kdf_cookie = rand;
        }
        sgx_spin_unlock(&g_ra_db_lock);
    }

    if(!p_context)
        return SGX_ERROR_INVALID_PARAMETER;

    //derive_key_cb can be NULL
    if (NULL != derive_key_cb &&
        !sgx_is_within_enclave((const void*)derive_key_cb, 0))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    //add new item to g_ra_db
    ra_db_item_t* new_item = (ra_db_item_t*)malloc(sizeof(ra_db_item_t));
    if (!new_item)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    memset(new_item, 0, sizeof(ra_db_item_t));
    if(b_pse)
    {
        //sgx_create_pse_session() must have been called
        ret = sgx_get_ps_sec_prop(&new_item->ps_sec_prop);
        if (ret!=SGX_SUCCESS)
        {
            SAFE_FREE(new_item);
            return ret;
        }
    }

    new_item->derive_key_cb = ENC_KDF_POINTER(derive_key_cb);
    new_item->state = ra_inited;

    sgx_spin_lock(&g_ra_db_lock);
    g_ra_db.push_back(new_item);
    *p_context = (nrt_ra_context_t)( g_ra_db.size() - 1 );
    sgx_spin_unlock(&g_ra_db_lock);
    return SGX_SUCCESS;
}

// TKE interface for isv enclaves
sgx_status_t nrt_ra_init(
    int b_pse,
    nrt_ra_context_t *p_context)
{

    return nrt_ra_init_ex(b_pse,
                          NULL,
                          p_context);
}

// TKE interface for isv enclaves
sgx_status_t nrt_ra_get_keys(
    nrt_ra_context_t context,
    sgx_ra_key_type_t type,
    sgx_ra_key_128_t *p_key)
{
    if(g_ra_db.size() <= context || !p_key)
        return SGX_ERROR_INVALID_PARAMETER;
    ra_db_item_t* item = g_ra_db[context];

    if(!sgx_is_within_enclave(p_key, sizeof(sgx_ra_key_128_t)))
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = SGX_SUCCESS;
    sgx_spin_lock(&item->item_lock);
    if (item->state != ra_keys_generated)
        ret = SGX_ERROR_INVALID_STATE;
    else if(SGX_RA_KEY_MK == type)
        memcpy(p_key, item->mk_key, sizeof(sgx_ra_key_128_t));
    else if(SGX_RA_KEY_SK == type)
        memcpy(p_key, item->sk_key, sizeof(sgx_ra_key_128_t));
    else
        ret = SGX_ERROR_INVALID_PARAMETER;
    sgx_spin_unlock(&item->item_lock);
    return ret;
}


// TKE interface for isv enclaves
sgx_status_t SGXAPI nrt_ra_close(
    nrt_ra_context_t context)
{
    if(g_ra_db.size() <= context)
        return SGX_ERROR_INVALID_PARAMETER;
    ra_db_item_t* item = g_ra_db[context];
    sgx_spin_lock(&g_ra_db_lock);
    //safe clear private key and RA key before free memory to defense in depth
    memset_s(&item->a,sizeof(item->a),0,sizeof(sgx_ec256_private_t));
    memset_s(&item->mk_key,sizeof(item->mk_key),0,sizeof(sgx_ec_key_128bit_t));
    memset_s(&item->sk_key,sizeof(item->sk_key),0,sizeof(sgx_ec_key_128bit_t));
    SAFE_FREE(item);
    g_ra_db.erase(g_ra_db.begin() + context);
    sgx_spin_unlock(&g_ra_db_lock);
    return SGX_SUCCESS;
}
