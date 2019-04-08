//
//  gnutls_nif.c
//  gnutls_nif
//
//  Created by Albin Stigö on 2019-04-07.
//  Copyright © 2019 Albin Stigo. All rights reserved.
//

#include <erl_nif.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <strings.h>
#include <errno.h>
#include <netinet/in.h>

#define MTU 1400
#define MAX_SRTP_KEY 256

/* Very handy... */
#define ERR_T(T) enif_make_tuple2(env, enif_make_atom(env, "error"), T)
#define GNUTLS_ERR_T(T) enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_string(env, gnutls_strerror(T), ERL_NIF_LATIN1))

#define OK_T(T) enif_make_tuple2(env, enif_make_atom(env, "ok"), T)

static ErlNifResourceType *gnutls_state_t = NULL;

typedef struct {
    gnutls_session_t session;
    gnutls_datum_t cookie_key;
    gnutls_dtls_prestate_st prestate;
    gnutls_certificate_credentials_t credentials;
    char *cert_file;
    char *key_file;
    ErlNifIOQueue *push_que;
    ErlNifIOQueue *pull_que;
} state_t;

ssize_t push_func(gnutls_transport_ptr_t p, const void *data, size_t size);
ssize_t pull_func(gnutls_transport_ptr_t p, void *data, size_t size);
static int pull_timeout_func(gnutls_transport_ptr_t p, unsigned int ms);

ssize_t push_func(gnutls_transport_ptr_t p, const void *data,
                  size_t size) {
    state_t* state = (state_t*)p;
    
    ErlNifBinary bin;
    enif_alloc_binary(size, &bin);
    // copy to binary
    memcpy(bin.data, data, size);
    //printf("push %ld\n", size);
    // enque
    if(!enif_ioq_enq_binary(state->push_que, &bin, 0)) {
        errno = ENOMEM;
        return -1;
    }
    
    return size;
}

ssize_t pull_func(gnutls_transport_ptr_t p, void *data, size_t size) {
    state_t* state = (state_t*)p;
    
    int iovlen;
    SysIOVec *iovec = enif_ioq_peek(state->pull_que, &iovlen);
    
    if(iovlen) {
        // printf("pull..");
        memcpy(data, iovec[0].iov_base, iovec[0].iov_len);
        enif_ioq_deq(state->pull_que, iovec[0].iov_len, NULL);
        return iovec[0].iov_len;
    }
    
    errno = EAGAIN;
    return -1;
}

static int pull_timeout_func(gnutls_transport_ptr_t p, unsigned int ms) {
    state_t* state = (state_t*)p;
    
    if (enif_ioq_size(state->pull_que) > 0) {
        return 1;
    }
    
    // errno = EAGAIN;
    return 0;
}

static void destroy_gnutls_state(ErlNifEnv *env, void *data) {
    state_t *state = (state_t *) data;
    
    enif_free(state->cert_file);
    enif_free(state->key_file);
    gnutls_certificate_free_credentials(state->credentials);
    gnutls_deinit(state->session);
    
    enif_ioq_destroy(state->push_que);
    enif_ioq_destroy(state->pull_que);
    
    memset(state, 0, sizeof(state_t));
}

static state_t *init_gnutls_state() {
    state_t *state = enif_alloc_resource(gnutls_state_t, sizeof(state_t));
    
    state->push_que = enif_ioq_create(ERL_NIF_IOQ_NORMAL);
    state->pull_que = enif_ioq_create(ERL_NIF_IOQ_NORMAL);
    
    return state;
}

static ERL_NIF_TERM open_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int err;
    ErlNifBinary certfile_bin;
    ErlNifBinary keyfile_bin;
    
    if (!enif_inspect_iolist_as_binary(env, argv[0], &certfile_bin))
        return enif_make_badarg(env);
    if (!enif_inspect_iolist_as_binary(env, argv[1], &keyfile_bin))
        return enif_make_badarg(env);
    
    state_t* state = init_gnutls_state();
    
    // Clear prestate
    memset(&state->prestate, 0, sizeof(gnutls_dtls_prestate_st));
    
    state->cert_file = enif_alloc(certfile_bin.size + 1);
    state->key_file = enif_alloc(keyfile_bin.size + 1);
    
    if (!state->cert_file || !state->key_file) {
        enif_release_resource(state);
        return ERR_T(enif_make_atom(env, "enomem"));
    }
    
    // 0 terminated C strings the hard way
    memcpy(state->cert_file, certfile_bin.data, certfile_bin.size);
    state->cert_file[certfile_bin.size] = '\0';
    memcpy(state->key_file, keyfile_bin.data, keyfile_bin.size);
    state->key_file[keyfile_bin.size] = '\0';
    
    err = gnutls_key_generate(&state->cookie_key, GNUTLS_COOKIE_KEY_SIZE);
    if (err != GNUTLS_E_SUCCESS) {
        enif_release_resource(state);
        return GNUTLS_ERR_T(err);
    }
    
    err = gnutls_init(&state->session, GNUTLS_SERVER | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK);
    if (err != GNUTLS_E_SUCCESS) {
        enif_release_resource(state);
        return GNUTLS_ERR_T(err);
    }
    
    err = gnutls_certificate_allocate_credentials(&state->credentials);
    if (err != GNUTLS_E_SUCCESS) {
        enif_release_resource(state);
        return GNUTLS_ERR_T(err);
    }
    
    err = gnutls_certificate_set_x509_key_file(state->credentials, state->cert_file, state->key_file, GNUTLS_X509_FMT_PEM);
    if (err != GNUTLS_E_SUCCESS) {
        enif_release_resource(state);
        return GNUTLS_ERR_T(err);
    }
    
    err = gnutls_credentials_set(state->session,
                                 GNUTLS_CRD_CERTIFICATE,
                                 state->credentials);
    if (err != GNUTLS_E_SUCCESS) {
        enif_release_resource(state);
        return GNUTLS_ERR_T(err);
    }
    
    err = gnutls_set_default_priority(state->session);
    if (err != GNUTLS_E_SUCCESS) {
        enif_release_resource(state);
        return GNUTLS_ERR_T(err);
    }
    
    /* Void functions */
    gnutls_dtls_set_mtu(state->session, MTU);
    gnutls_transport_set_ptr(state->session, state);
    gnutls_srtp_set_profile(state->session, GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80);
    gnutls_transport_set_push_function(state->session, push_func);
    gnutls_transport_set_pull_function(state->session, pull_func);
    gnutls_transport_set_pull_timeout_function(state->session, pull_timeout_func);
    
    ERL_NIF_TERM result = enif_make_resource(env, state);
    
    enif_release_resource(state);
    return OK_T(result);
}

static ERL_NIF_TERM cookie_verify_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int err;
    ErlNifBinary client_data_bin;
    ErlNifBinary cookie_bin;
    state_t *state = NULL;
    
    if (!enif_get_resource(env, argv[0], gnutls_state_t, (void *) &state))
        return enif_make_badarg(env);
    
    if (!enif_inspect_iolist_as_binary(env, argv[1], &client_data_bin))
        return enif_make_badarg(env);
    
    if (!enif_inspect_iolist_as_binary(env, argv[2], &cookie_bin))
        return enif_make_badarg(env);
    
    err = gnutls_dtls_cookie_verify(&state->cookie_key,
                                    client_data_bin.data,
                                    client_data_bin.size,
                                    cookie_bin.data, cookie_bin.size,
                                    &state->prestate);
    
    if (err == GNUTLS_E_SUCCESS) {
        // Ok associate with session
        gnutls_dtls_prestate_set(state->session, &state->prestate);
        return enif_make_atom(env, "ok");
    }
    
    return GNUTLS_ERR_T(err);
}

static ERL_NIF_TERM push_que_to_bin_list(ErlNifEnv* env, state_t* state) {
    ERL_NIF_TERM array[10];
    ERL_NIF_TERM list;
    size_t size = 0;
    int i = 0;
    
    // Fix this shit
    
    while(enif_ioq_peek_head(env, state->push_que, &size, &array[i++])) {
        enif_ioq_deq(state->push_que, size, &size);
    }
    list = enif_make_list_from_array(env, array, i-1);
    
    return list;
}

static ERL_NIF_TERM cookie_send_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int err;
    ErlNifBinary client_data_bin;
    state_t *state = NULL;
    
    if (!enif_get_resource(env, argv[0], gnutls_state_t, (void *) &state))
        return enif_make_badarg(env);
    
    if (!enif_inspect_iolist_as_binary(env, argv[1], &client_data_bin))
        return enif_make_badarg(env);
    
    err = gnutls_dtls_cookie_send(&state->cookie_key,
                                  client_data_bin.data,
                                  client_data_bin.size,
                                  &state->prestate,
                                  (gnutls_transport_ptr_t) state,
                                  push_func);
    
    if (err > 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                                push_que_to_bin_list(env, state));
    }
    
    return GNUTLS_ERR_T(err);
}

static ERL_NIF_TERM handshake_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int err;
    ErlNifBinary recv_bin;
    state_t *state = NULL;
    
    if (!enif_get_resource(env, argv[0], gnutls_state_t, (void *) &state))
        return enif_make_badarg(env);
    
    if (!enif_inspect_iolist_as_binary(env, argv[1], &recv_bin))
        return enif_make_badarg(env);
    
    // Add received packet to queue
    if (!enif_ioq_enq_binary(state->pull_que, &recv_bin, 0))
        return ERR_T(enif_make_atom(env, "enomem"));
    
    // Perform handshake
    err = gnutls_handshake(state->session);
    
    if(err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED) {
        return enif_make_tuple2(env, enif_make_atom(env, "again"),
                                push_que_to_bin_list(env, state));
    } else if(err == GNUTLS_E_SUCCESS) {
        return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                                push_que_to_bin_list(env, state));
    }
    
    return GNUTLS_ERR_T(err);
}

static ERL_NIF_TERM record_recv_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ssize_t err;
    ErlNifBinary recv_bin;
    ErlNifBinary clear_bin;
    state_t *state = NULL;
    
    if (!enif_get_resource(env, argv[0], gnutls_state_t, (void *) &state))
        return enif_make_badarg(env);
    
    if (!enif_inspect_iolist_as_binary(env, argv[1], &recv_bin))
        return enif_make_badarg(env);
    
    // Add received packet to queue
    if (!enif_ioq_enq_binary(state->pull_que, &recv_bin, 0))
        return ERR_T(enif_make_atom(env, "enomem"));
    
    if(!enif_alloc_binary(MTU, &clear_bin))
        return ERR_T(enif_make_atom(env, "enomem"));
    
    err = gnutls_record_recv(state->session, clear_bin.data, clear_bin.size);
    if(err >= 0) {
        enif_realloc_binary(&clear_bin, err);
        return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                                enif_make_binary(env, &clear_bin));
    }
    
    enif_release_binary(&clear_bin);
    return GNUTLS_ERR_T((int)err);
}

static ERL_NIF_TERM record_send_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ssize_t err;
    ErlNifBinary send_bin;
    state_t *state = NULL;
    
    if (!enif_get_resource(env, argv[0], gnutls_state_t, (void *) &state))
        return enif_make_badarg(env);
    
    if (!enif_inspect_iolist_as_binary(env, argv[1], &send_bin))
        return enif_make_badarg(env);
    
    err = gnutls_record_send(state->session, send_bin.data, send_bin.size);
    if(err >= 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                                push_que_to_bin_list(env, state));
    }
    
    return GNUTLS_ERR_T((int)err);
}

static ERL_NIF_TERM srtp_get_keys_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int err;
    unsigned char key_material[MAX_SRTP_KEY];
    ErlNifBinary client_key_bin;
    ErlNifBinary client_salt;
    ErlNifBinary server_key;
    ErlNifBinary server_salt;
    state_t *state = NULL;
    
    gnutls_datum_t client_key_datum;
    gnutls_datum_t client_salt_datum;
    gnutls_datum_t server_key_datum;
    gnutls_datum_t server_salt_datum;
    
    if (!enif_get_resource(env, argv[0], gnutls_state_t, (void *) &state))
        return enif_make_badarg(env);
    
    /* TODO: Not sure about the key sizes
     gnutls_srtp_profile_t profile;
     err = gnutls_srtp_get_selected_profile(state->session, &profile);
     if (err != GNUTLS_E_SUCCESS)
     return GNUTLS_ERR_T(err);*/
    
    // Get keys
    err = gnutls_srtp_get_keys(state->session,
                               key_material,
                               MAX_SRTP_KEY,
                               &client_key_datum,
                               &client_salt_datum,
                               &server_key_datum,
                               &server_salt_datum);
    
    if (err > 0) {
        // Might leak a few buffers here but that's hardly a problem if we
        // are so low on memory.
        if(!enif_alloc_binary(client_key_datum.size, &client_key_bin) ||
           !enif_alloc_binary(client_salt_datum.size, &client_salt) ||
           !enif_alloc_binary(server_key_datum.size, &server_key) ||
           !enif_alloc_binary(server_salt_datum.size, &server_salt))
            return ERR_T(enif_make_atom(env, "enomem"));
        
        memcpy(client_key_bin.data, client_key_datum.data, client_key_datum.size);
        memcpy(client_salt.data, client_salt_datum.data, client_salt_datum.size);
        memcpy(server_key.data, server_key_datum.data, server_key_datum.size);
        memcpy(server_salt.data, server_salt_datum.data, server_salt_datum.size);
        // Return tuple with keys
        enif_make_tuple5(env,
                         enif_make_atom(env, "ok"),
                         enif_make_binary(env, &client_key_bin),
                         enif_make_binary(env, &client_salt),
                         enif_make_binary(env, &server_key),
                         enif_make_binary(env, &server_salt));
    }
    
    return GNUTLS_ERR_T(err);
}

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info) {
    
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    gnutls_state_t = enif_open_resource_type(env, NULL, "gnutls_state_t",
                                             destroy_gnutls_state,
                                             flags, NULL);
    
    return 0;
}

static void unload(ErlNifEnv *env, void *priv) {
    
}

static ErlNifFunc nif_funcs[] =
{
    {"record_recv_nif", 2, record_recv_nif},
    {"record_send_nif", 2, record_send_nif},
    {"cookie_verify_nif", 3, cookie_verify_nif},
    {"cookie_send_nif", 2, cookie_send_nif},
    {"handshake_nif", 2, handshake_nif},
    {"srtp_get_keys_nif", 1, srtp_get_keys_nif},
    {"open_nif", 2, open_nif},
};

ERL_NIF_INIT(gen_gnutls, nif_funcs, load, NULL, NULL, unload);
