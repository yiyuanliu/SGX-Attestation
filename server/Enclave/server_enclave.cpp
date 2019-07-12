#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "dh_session_protocol.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"
#include "server_enclave_t.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"


session_id_tracker_t *tracker;
dh_session_t session;

#define SUCCESS 0

#define MSG_TYPE_TEST       0
#define MSG_TYPE_GET_KEY    1
#define MSG_TYPE_SIG_DATA   2

#define RSA_3072_MOD_SIZE   384 //hardcode n size to be 384
#define RSA_3072_EXP_SIZE     4 //hardcode e size to be 4

#define REF_N_SIZE_IN_BYTES    384
#define REF_E_SIZE_IN_BYTES    4
#define REF_D_SIZE_IN_BYTES    384
#define REF_P_SIZE_IN_BYTES    192
#define REF_Q_SIZE_IN_BYTES    192
#define REF_DMP1_SIZE_IN_BYTES 192
#define REF_DMQ1_SIZE_IN_BYTES 192
#define REF_IQMP_SIZE_IN_BYTES 192

typedef struct _ref_rsa_params_t {
    unsigned char n[REF_N_SIZE_IN_BYTES];
    unsigned char e[REF_E_SIZE_IN_BYTES];
    unsigned char d[REF_D_SIZE_IN_BYTES];
    unsigned char p[REF_P_SIZE_IN_BYTES];
    unsigned char q[REF_Q_SIZE_IN_BYTES];
    unsigned char dmp1[REF_DMP1_SIZE_IN_BYTES];
    unsigned char dmq1[REF_DMQ1_SIZE_IN_BYTES];
    unsigned char iqmp[REF_IQMP_SIZE_IN_BYTES];
}ref_rsa_params_t;

sgx_rsa3072_public_key_t pub_key;
sgx_rsa3072_key_t key;


static void 
log(const char *str) {
    log_ocall(NULL, str);
}

static void
gen_rsa_key() {
    ref_rsa_params_t g_rsa_key = { 0 };
    *((unsigned int*)g_rsa_key.e) = 0x10001;
    sgx_status_t ret_code = sgx_create_rsa_key_pair(RSA_3072_MOD_SIZE,
            RSA_3072_EXP_SIZE,
            g_rsa_key.n,
            g_rsa_key.d,
            g_rsa_key.e,
            g_rsa_key.p,
            g_rsa_key.q,
            g_rsa_key.dmp1,
            g_rsa_key.dmq1,
            g_rsa_key.iqmp);
    if (ret_code != SGX_SUCCESS) {
        char buf[100];
        snprintf(buf, 100, "%d", ret_code);
        log("Gen rsa key pair failed.");
        log(buf);
        return;
    }
    memcpy(key.mod, g_rsa_key.n, sizeof(g_rsa_key.n));
    memcpy(key.d, g_rsa_key.d, sizeof(g_rsa_key.d));
    memcpy(key.e, g_rsa_key.e, sizeof(g_rsa_key.e));
    memcpy(pub_key.mod, g_rsa_key.n, sizeof(g_rsa_key.n));
    memcpy(pub_key.exp, g_rsa_key.e, sizeof(g_rsa_key.e));

    log("Key generated.");

    sgx_rsa3072_signature_t sig;
    sgx_rsa3072_sign((const uint8_t*)"0123456789", 11, &key, &sig);
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((const uint8_t*)"0123456789", 11, &pub_key, &sig, &result);
    if (result == SGX_RSA_VALID) {
        // log("Sig test successed.");
    } else {
        log("Sig test failed.");
    }
}

static uint32_t
verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity) {
    if(!peer_enclave_identity) {
        return -1;
    }
    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED)) {
        return -1;
    } else {
        return SUCCESS;
    }
}

uint32_t session_request(sgx_dh_msg1_t *dh_msg1, uint32_t *session_id) {
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    //Intialize the session as a session responder
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status) {
        return -1;
    }
    
    //get a new SessionID
    *session_id = 0;

    //Allocate memory for the session id tracker
    tracker = (session_id_tracker_t *)malloc(sizeof(session_id_tracker_t));
    memset(tracker, 0, sizeof(session_id_tracker_t));
    tracker->session_id = *session_id;
    session_info.status = IN_PROGRESS;

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status) {
        SAFE_FREE(tracker);
        return status;
    }
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    session = session_info;
    
    return status;
}

uint32_t exchange_report(sgx_dh_msg2_t *dh_msg2,
                          sgx_dh_msg3_t *dh_msg3,
                          uint32_t session_id) {
    sgx_key_128bit_t dh_aek;   // Session key
    dh_session_t *session_info;
    uint32_t status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t initiator_identity;

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    session_info = &session;
    if(session_info->status != IN_PROGRESS) {
        status = -1;

    }

    memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

    dh_msg3->msg3_body.additional_prop_length = 0;
    sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2, 
                                                    dh_msg3, 
                                                    &sgx_dh_session, 
                                                    &dh_aek, 
                                                    &initiator_identity);
    if(SGX_SUCCESS != se_ret) {
        status = se_ret;
    }

    //Verify source enclave's trust
    if (verify_peer_enclave_trust(&initiator_identity) != 0) {
        log("Verify peer failed.");
        return -1;
    } else {
        log("Peer verified!");
    }

    //save the session ID, status and initialize the session nonce
    session_info->session_id = session_id;
    session_info->status = ACTIVE;
    session_info->active.counter = 0;
    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));

    if(status != SUCCESS) {
        
    }

    return status;
}

uint32_t generate_response(secure_message_t* req_message,
                            size_t req_message_size,
                            size_t max_payload_size,
                            secure_message_t* resp_message,
                            size_t resp_message_size) {
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    ms_in_msg_exchange_t * ms;
    size_t resp_data_length;
    size_t resp_message_calc_size;
    char* resp_data;
    uint8_t l_tag[TAG_SIZE];
    size_t header_size, expected_payload_size;
    dh_session_t *session_info;
    secure_message_t* temp_resp_message;
    uint32_t ret;
    sgx_status_t status;

    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!req_message || !resp_message) {
        return -1;
    }

    //Get the session information from the map corresponding to the source enclave id
    session_info = &session;
    if(session_info->status != ACTIVE)
    {
        return -1;
    }

    //Set the decrypted data length to the payload size obtained from the message
    decrypted_data_length = req_message->message_aes_gcm_data.payload_size;

    header_size = sizeof(secure_message_t);
    expected_payload_size = req_message_size - header_size;

    //Verify the size of the payload
    if(expected_payload_size != decrypted_data_length)
        return -1;

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);

    memset(decrypted_data, 0, decrypted_data_length);

    //Decrypt the request message payload from source enclave
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, req_message->message_aes_gcm_data.payload, 
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), &(req_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length, 
                &req_message->message_aes_gcm_data.payload_tag);

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(decrypted_data);
        return status;
    }

    //Casting the decrypted data to the marshaling structure type to obtain type of request (generic message exchange/enclave to enclave call)
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    // Verify if the nonce obtained in the request is equal to the session nonce
    if((uint32_t)*(req_message->message_aes_gcm_data.reserved) != session_info->active.counter || *(req_message->message_aes_gcm_data.reserved) > ((2^32)-2)) {
        SAFE_FREE(decrypted_data);
        return -1;
    }

    if(ms->msg_type == MSG_TYPE_GET_KEY) {
        log("Receive get pub key request from client, send public key.");
        resp_data_length = sizeof(pub_key);
        resp_data = (char*)malloc(resp_data_length);
        memcpy(resp_data, &pub_key, resp_data_length);
    } else if (ms->msg_type == MSG_TYPE_SIG_DATA) {
        log("Receive sign data request from client.");
        sgx_rsa3072_signature_t *sig = (sgx_rsa3072_signature_t*)malloc(sizeof(sgx_rsa3072_signature_t));
        sgx_rsa3072_sign((const uint8_t*)ms->inparam_buff, ms->inparam_buff_len, &key, sig);
        char buf[100];
        snprintf(buf, 100, "len %d, %s", ms->inparam_buff_len, ms->inparam_buff);
        log(buf);
        resp_data = (char*)sig;
        resp_data_length = sizeof(sgx_rsa3072_signature_t);
        log("Signature generated, respond to client.");
    }

    resp_message_calc_size = sizeof(secure_message_t)+ resp_data_length;

    if(resp_message_calc_size > resp_message_size) {
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        return -1;
    }

    //Code to build the response back to the Source Enclave
    temp_resp_message = (secure_message_t*)malloc(resp_message_calc_size);
    if(!temp_resp_message) {
            SAFE_FREE(resp_data);
            SAFE_FREE(decrypted_data);
            return -1;
    }

    memset(temp_resp_message,0,sizeof(secure_message_t)+ resp_data_length);
    const uint32_t data2encrypt_length = (uint32_t)resp_data_length;
    temp_resp_message->session_id = session_info->session_id;
    temp_resp_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Increment the Session Nonce (Replay Protection)
    session_info->active.counter = session_info->active.counter + 1;

    //Set the response nonce as the session nonce
    memcpy(&temp_resp_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));

    //Prepare the response message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)resp_data, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(temp_resp_message->message_aes_gcm_data.reserved)),
                sizeof(temp_resp_message->message_aes_gcm_data.reserved), plaintext, plaintext_length, 
                &(temp_resp_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status) {
        SAFE_FREE(resp_data);
        SAFE_FREE(decrypted_data);
        SAFE_FREE(temp_resp_message);
        return status;
    }

    memset(resp_message, 0, sizeof(secure_message_t)+ resp_data_length);
    memcpy(resp_message, temp_resp_message, sizeof(secure_message_t)+ resp_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(resp_data);
    SAFE_FREE(temp_resp_message);

    return SUCCESS;
}

uint32_t run_server() {
    uint32_t status;
    log("Wait client request.");
    status = wait_dh_request_ocall(NULL);
    if (status) {
        log("Wait dh request failed.");
        return 1;
    }

    sgx_dh_msg1_t dh_msg1;
    uint32_t session_id; 
    status = session_request(&dh_msg1, &session_id);
    if (status) {
        log("Failed to handle session request.");
        return 1;
    }
    log("Send msg1 and session id.");
    status = send_msg1_ocall(NULL, &dh_msg1, &session_id);
    if (status) {
        log("Msg1 send failed.");
        return 1;
    }

    sgx_dh_msg2_t dh_msg2;
    sgx_dh_msg3_t dh_msg3;
    log("Wait msg2.");
    status = recv_msg2_ocall(NULL, &dh_msg2, &session_id);
    if (status) {
        log("Recv msg2 failed.");
        return 1;
    }
    status = exchange_report(&dh_msg2, &dh_msg3, session_id);
    if (status) {
        log("Report exchange failed.");
        return -1;
    }
    log("Try to send msg3.");
    send_msg3_ocall(NULL, &dh_msg3);

    log("Session created!");

    log("-------------------------------------");

    gen_rsa_key();

    char req_msg[4096], respon_msg[4096];
    size_t req_message_size;
    size_t max_payload_size;
    recv_request_ocall(NULL, (secure_message_t*)req_msg, &req_message_size, &max_payload_size);
    generate_response((secure_message_t*)req_msg, req_message_size, max_payload_size, (secure_message_t*)respon_msg, 4096);
    send_response_ocall(NULL, (secure_message_t*)respon_msg, 4096);

    recv_request_ocall(NULL, (secure_message_t*)req_msg, &req_message_size, &max_payload_size);
    generate_response((secure_message_t*)req_msg, req_message_size, max_payload_size, (secure_message_t*)respon_msg, 4096);
    send_response_ocall(NULL, (secure_message_t*)respon_msg, 4096);
    return 0;
}