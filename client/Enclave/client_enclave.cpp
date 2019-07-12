#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "dh_session_protocol.h"
#include "sgx_dh.h"
#include "sgx_tcrypto.h"
#include "client_enclave_t.h"
#include "assert.h"
#include "string.h"
#include "datatypes.h"
#include "stdlib.h"

#define SUCCESS 0

#define MSG_TYPE_TEST       0
#define MSG_TYPE_GET_KEY    1
#define MSG_TYPE_SIG_DATA   2

sgx_rsa3072_public_key_t pub_key;

static uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);

void log(const char *str) {
    uint32_t retstatus;
    log_ocall(&retstatus, str);
}

static void gen_msg(uint32_t msg_type, void *data, uint32_t data_len, void **msg, uint32_t *msg_len) {
    *msg_len = sizeof(ms_in_msg_exchange_t) + data_len;
    ms_in_msg_exchange_t *ms = (ms_in_msg_exchange_t*)malloc(*msg_len);
    ms->msg_type = msg_type;
    ms->target_fn_id = 0;
    ms->inparam_buff_len = data_len;
    memcpy(&ms->inparam_buff, data, data_len);
    *msg = ms;
}

uint32_t 
session_request(sgx_dh_msg1_t* dh_msg1, 
                uint32_t* session_id) {
    uint32_t retstatus;
    sgx_status_t status;
    status = send_ocall(&retstatus, (void*)"req session", 10);
    assert(status == SGX_SUCCESS);
    
    recv_ocall(&retstatus, dh_msg1, sizeof(sgx_dh_msg1_t));
    recv_ocall(&retstatus, session_id, sizeof(uint32_t));
    return 0;
}

uint32_t 
exchange_report(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id) {
    uint32_t retstatus;
    log("Exchange report: send msg2 and wait msg3.");
    send_ocall(&retstatus, &session_id, sizeof(uint32_t));
    send_ocall(&retstatus, dh_msg2, sizeof(sgx_dh_msg2_t));

    recv_ocall(&retstatus, dh_msg3, sizeof(sgx_dh_msg3_t));
    return 0;
}

uint32_t
send_request(secure_message_t* req_message, 
                    size_t req_message_size, 
                    size_t max_payload_size, 
                    secure_message_t* resp_message, 
                    size_t resp_message_size) {
    uint32_t retstatus;
    send_ocall(&retstatus, &req_message_size, sizeof(size_t));
    send_ocall(&retstatus, &max_payload_size, sizeof(size_t));
    send_ocall(&retstatus, req_message, req_message_size);

    recv_ocall(&retstatus, resp_message, resp_message_size);
    return 0;
}

uint32_t
end_session() {
    uint32_t retstatus;
    send_ocall(&retstatus, (void*)"close session", 10);
    (void) retstatus;
    return 0;
}

uint32_t 
create_session(dh_session_t *session_info) {
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;        // Session Key
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    uint32_t session_id;
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    assert(session_info);

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(status == SGX_SUCCESS) {
        log("Sgx dh init session success.");
    } else {
        log("Sgx db init failed.");
        return -1;
    }

    log("Request succession, wait msg1.");
    retstatus = session_request(&dh_msg1, &session_id);
    if (retstatus != 0) {
        log("Session request failed.");
        return -1;
    }

    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if (status == SUCCESS) {
        log("Sgx dh initator proc msg1 success.");
    } else {
        log("Proc msg1 failed;");
        return -1;
    }

    retstatus = exchange_report(&dh_msg2, &dh_msg3, session_id);
    if (retstatus == 0) {
        // log("Exchange report success.");
    } else {
        // log("Exchange report failed.");
    }

    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if (status == SGX_SUCCESS) {
        log("Proc msg3 success.");
    } else {
        log("Proc msg3 failed.");
        return -1;
    }

    if (verify_peer_enclave_trust(&responder_identity) != 0) {
        log("Verify peer failed.");
        return -1;
    } else {
        log("Peer verified!");
    }

    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    session_info->session_id = session_id;
    session_info->active.counter = 0;
    session_info->status = ACTIVE;
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    return status;
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

static uint32_t
send_request_receive_response(dh_session_t *session_info,
                                char *inp_buff,
                                size_t inp_buff_len,
                                size_t max_out_buff_size,
                                char **out_buff,
                                size_t* out_buff_len) {
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    uint32_t retstatus;
    secure_message_t* req_message;
    secure_message_t* resp_message;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    uint8_t l_tag[TAG_SIZE];
    size_t max_resp_message_length;
    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    //Check if the nonce for the session has not exceeded 2^32-2 if so end session and start a new session
    assert(session_info->active.counter < ((uint32_t) - 2));

    //Allocate memory for the AES-GCM request message
    req_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ inp_buff_len);


    memset(req_message,0,sizeof(secure_message_t)+ inp_buff_len);
    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;
    //Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved,&session_info->active.counter,sizeof(session_info->active.counter));


    //Set the session ID of the message to the current session id
    req_message->session_id = session_info->session_id;

    //Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)inp_buff, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), plaintext, plaintext_length, 
                &(req_message->message_aes_gcm_data.payload_tag));

    assert(status == SGX_SUCCESS);

    
    //Allocate memory for the response payload to be copied
    *out_buff = (char*)malloc(max_out_buff_size);
    assert(out_buff);
    memset(*out_buff, 0, max_out_buff_size);

    //Allocate memory for the response message
    resp_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ max_out_buff_size);
    assert(resp_message);

    memset(resp_message, 0, sizeof(secure_message_t)+ max_out_buff_size);

    //Ocall to send the request to the Destination Enclave and get the response message back
    retstatus = send_request(req_message,
                          (sizeof(secure_message_t)+ inp_buff_len), 
                          max_out_buff_size,
                                resp_message, (sizeof(secure_message_t)+ max_out_buff_size));
    assert (retstatus == SUCCESS);

    max_resp_message_length = sizeof(secure_message_t)+ max_out_buff_size;

    if(sizeof(resp_message) > max_resp_message_length) {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return -1;
    }

    //Code to process the response message from the Destination Enclave

    decrypted_data_length = resp_message->message_aes_gcm_data.payload_size;
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    
    memset(&l_tag, 0, 16);

    memset(decrypted_data, 0, decrypted_data_length);

    //Decrypt the response message payload
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, resp_message->message_aes_gcm_data.payload, 
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                sizeof(resp_message->message_aes_gcm_data.reserved), &(resp_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length, 
                &resp_message->message_aes_gcm_data.payload_tag);
    
    assert(SGX_SUCCESS == status);

    // Verify if the nonce obtained in the response is equal to the session nonce + 1 (Prevents replay attacks)
    assert(*(resp_message->message_aes_gcm_data.reserved) == (session_info->active.counter + 1 ));

    //Update the value of the session nonce in the source enclave
    session_info->active.counter = session_info->active.counter + 1;

    memcpy(out_buff_len, &decrypted_data_length, sizeof(decrypted_data_length));
    memcpy(*out_buff, decrypted_data, decrypted_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(req_message);
    SAFE_FREE(resp_message);
    return SUCCESS;
}

uint32_t close_session() {
    sgx_status_t status;
    uint32_t retstatus;
    retstatus = end_session();
    assert(retstatus == SUCCESS);

    return SUCCESS;
}

uint32_t
run_client(void) {
    uint32_t status;
    dh_session_t session;
    status = create_session(&session);
    if (status == 0) {
        log("Session created!");
    }
    log("-------------------------------------");
    void *msg;
    uint32_t msg_len;
    gen_msg(MSG_TYPE_GET_KEY, (void *)"get key", 8, &msg, &msg_len);
    char *out_buf;
    size_t out_buf_len;
    send_request_receive_response(&session, (char*)msg, msg_len, 4096, &out_buf, &out_buf_len);
    log("Get public key.");
    memcpy(&pub_key, out_buf, sizeof(pub_key));

    log("Request sign data.");
    char str[] = "This is a string to sign.";
    int str_len = strlen(str) + 1;
    gen_msg(MSG_TYPE_SIG_DATA, str, str_len, &msg, &msg_len);
    send_request_receive_response(&session, (char*)msg, msg_len, 4096, &out_buf, &out_buf_len);
    log("Get data signature, verify it.");
    sgx_rsa3072_signature_t sig;
    memcpy(&sig, out_buf, sizeof(sig));
    sgx_rsa_result_t result;
    sgx_rsa3072_verify((const uint8_t*)str, str_len, &pub_key, &sig, &result);
    if (result == SGX_RSA_VALID) {
        log("Signature verified!");
    } else {
        log("Signature verify failed.");
    }
}