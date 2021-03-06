/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file hashmessagetest.c
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-01-28
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hash_message.h"
#include "hash_message_cbor.h"

#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include "mbedtls/version.h"
#include "../src/util/cbor_util.h"

/*
 * CUnit Test Suite
 */

uint8_t test_hm[133] = {
    /*complete size   */ 99, 0, 62,
    /*  PCR           */ 1, 1, 16,
    /*INTERPRETER_NAME*/ 2, 4, 'T', 'E', 'S', 'T',
    /*  SCRIPT_NAME   */ 3, 8, 'T', 'E', 'S', 'T', 'F', 'I', 'L', 'E',
    /*  HASH_PL_SIZE  */ 4, 1, 2,
    /*  HASH_PL       */ 5, 106,
    /*  HASH_ALG  1   */ 6, 1, 1,
    /*  HASH_DATA 1   */ 7, 32, 49, 95, 91, 219, 118, 208, 120, 196, 59, 138, 192, 6, 78, 74, 1, 100, 97, 43, 31, 206, 119, 200, 105, 52, 91, 252, 148, 199, 88, 148, 237, 211,
    /*  HASH_ALG  2   */ 6, 1, 3,
    /*  HASH_DATA 2   */ 7, 64, 188, 97, 136, 41, 61, 144, 154, 53, 234, 55, 108, 247, 128, 92, 211, 171, 127, 74, 207, 10, 196, 147, 78, 84, 77, 32, 74, 157, 67, 188, 250, 209, 25, 33, 28, 73, 205, 47, 164, 9, 221, 205, 77, 141, 128, 209, 255, 5, 201, 167, 99, 233, 105, 77, 231, 190, 118, 94, 34, 231, 6, 154, 190, 74
};

uint8_t test_cbor[121] = {
    /* array(4)     */ 0x84,
    /* unsigned(16)     */ 0x10,
    /* text(4)          */ 0x64,
    /* "TEST"               */ 0x54, 0x45, 0x53, 0x54,
    /* text(8)          */ 0x68,
    /* "TESTFILE"           */ 0x54, 0x45, 0x53, 0x54, 0x46, 0x49, 0x4c, 0x45,
    /* array(2)         */ 0x82,
    /* array(2)             */ 0x82,
    /* unsigned(11)             */ 0x0b,
    /* bytes(32)                */ 0x58, 0x20,
    /* hashvalue 1                  */ 0x8c, 0xee, 0x5d, 0x76, 0x67, 0xb8, 0xc5, 0x50, 0x7b, 0xd1, 0x04, 0x25, 0xfc, 0x90, 0x62, 0xdd, 0x5f, 0x30, 0xc7, 0x19, 0x08, 0x6a, 0x47, 0x70, 0x0c, 0x79, 0xd4, 0x12, 0xb8, 0x5e, 0xb3, 0x0c,
    /* array(2)             */ 0x82,
    /* unsigned(13)             */ 0x0d,
    /* bytes(64)                */ 0x58, 0x40,
    /* hashvalue 2                  */ 0xbc, 0x61, 0x88, 0x29, 0x3d, 0x90, 0x9a, 0x35, 0xea, 0x37, 0x6c, 0xf7, 0x80, 0x5c, 0xd3, 0xab, 0x7f, 0x4a, 0xcf, 0x0a, 0xc4, 0x93, 0x4e, 0x54, 0x4d, 0x20, 0x4a, 0x9d, 0x43, 0xbc, 0xfa, 0xd1, 0x19, 0x21, 0x1c, 0x49, 0xcd, 0x2f, 0xa4, 0x09, 0xdd, 0xcd, 0x4d, 0x8d, 0x80, 0xd1, 0xff, 0x05, 0xc9, 0xa7, 0x63, 0xe9, 0x69, 0x4d, 0xe7, 0xbe, 0x76, 0x5e, 0x22, 0xe7, 0x06, 0x9a, 0xbe, 0x4a
};
uint8_t test_cbor2[243] = {
    0x84, 0x10, 0x64, 0x54, 0x45, 0x53,
    0x54, 0x78, 0x81, 0x2f, 0x64, 0x61, 
    0x73, 0x2f, 0x69, 0x73, 0x74, 0x2f, 
    0x65, 0x69, 0x6e, 0x2f, 0x73, 0x65, 
    0x68, 0x72, 0x2f, 0x73, 0x65, 0x68, 
    0x72, 0x2f, 0x73, 0x65, 0x68, 0x72, 
    0x2f, 0x73, 0x65, 0x68, 0x72, 0x2f, 
    0x73, 0x65, 0x68, 0x72, 0x2f, 0x73, 
    0x65, 0x68, 0x72, 0x2f, 0x73, 0x65, 
    0x68, 0x72, 0x2f, 0x73, 0x65, 0x68, 
    0x72, 0x2f, 0x73, 0x65, 0x68, 0x72, 
    0x2f, 0x73, 0x65, 0x68, 0x72, 0x2f, 
    0x73, 0x65, 0x68, 0x72, 0x2f, 0x73, 
    0x65, 0x68, 0x72, 0x2f, 0x73, 0x65, 
    0x68, 0x72, 0x2f, 0x73, 0x65, 0x68,
    0x72, 0x2f, 0x73, 0x65, 0x68, 0x72, 
    0x2f, 0x73, 0x65, 0x68, 0x72, 0x2f, 
    0x73, 0x65, 0x68, 0x72, 0x2f, 0x73, 
    0x65, 0x68, 0x72, 0x2f, 0x73, 0x65, 
    0x68, 0x72, 0x2f, 0x73, 0x65, 0x68, 
    0x72, 0x2f, 0x73, 0x65, 0x68, 0x72, 
    0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x65, 
    0x72, 0x2f, 0x70, 0x66, 0x61, 0x64, 
    0x82, 0x82, 0x0b, 0x58, 0x20, 0x3d, 
    0xe5, 0x64, 0xb0, 0x16, 0x2c, 0x76, 
    0xef, 0xe3, 0x2f, 0x12, 0x60, 0x00, 
    0xf7, 0xaf, 0x65, 0xf1, 0x42, 0x7f, 
    0xf8, 0x44, 0x17, 0x2d, 0x62, 0x6b, 
    0x4d, 0x13, 0xb3, 0x4b, 0x69, 0x26, 
    0x61, 0x82, 0x0d, 0x58, 0x40, 0x0d, 
    0x81, 0x06, 0x92, 0x65, 0x27, 0x95, 
    0x75, 0xe1, 0x17, 0xb6, 0xb8, 0x5d, 
    0xb4, 0xfc, 0xa9, 0xa6, 0xe0, 0x53, 
    0x0e, 0x09, 0x8e, 0xa9, 0x46, 0x61, 
    0xfa, 0x79, 0x02, 0x84, 0x85, 0xfd, 
    0x7a, 0x79, 0xba, 0x0f, 0xfd, 0x22, 
    0xfb, 0xe9, 0xcc, 0xa1, 0x78, 0xaa, 
    0xa3, 0x7b, 0x90, 0xa6, 0x94, 0x6e, 
    0x5a, 0x27, 0xce, 0x7c, 0xce, 0x5d, 
    0x4e, 0x39, 0x23, 0x0f, 0x27, 0x95, 
    0x24, 0xe8, 0x46
};

int init_suite(void) {

    return 0;
}

int clean_suite(void) {
    return 0;
}

void test1() {
    uint8_t *output = calloc(32, sizeof (uint8_t)); /* SHA-256 outputs 32 bytes */
    uint8_t *output2 = calloc(64, sizeof (uint8_t));
    mbedtls_sha256_context ctx2;
    mbedtls_sha512_context ctx1;

    mbedtls_sha512_init(&ctx1);

    mbedtls_sha512_starts_ret(&ctx1, 0);

    mbedtls_sha256_init(&ctx2);
    mbedtls_sha256_starts_ret(&ctx2,
            0); /* 0 here means use the full SHA-256, not the SHA-224 variant */
    const char *str = "/das/ist/ein/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/sehr/langer/pfad";
    mbedtls_sha512_update_ret(&ctx1, (unsigned char *) str, strlen(str));
    mbedtls_sha256_update_ret(&ctx2, (unsigned char *) str, strlen(str));
    mbedtls_sha256_finish_ret(&ctx2, output);
    mbedtls_sha512_finish_ret(&ctx1, output2);
    mbedtls_sha512_free(&ctx1);
    mbedtls_sha256_free(&ctx2);

    for (int i = 0; i < 32; i++) {
        printf("%02x", output[i]);
    }
    printf("\r\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x", output2[i]);
    }
    printf("\r\n");
    hash_message hm;
    char *str2 = "TEST";
    hm.intp_name = malloc(1 + strlen(str2));
    strcpy(hm.intp_name, str2);
    hm.payload_size = 2;
    hm.script_name = malloc(strlen(str) + 1);
    strcpy(hm.script_name, str);
    hm.script_name_length = strlen(str);
    hm.intp_name_length = strlen(hm.intp_name);
    hm.pcr = 16;
    hm.h_payload = (hash_payload*) calloc(2, sizeof (struct hash_payload));
    hm.h_payload[0].alg_name = TPM2_ALG_SHA256;
    hm.h_payload[0].hash_data = output;
    hm.h_payload[1].alg_name = TPM2_ALG_SHA512;
    hm.h_payload[1].hash_data = output2;

    uint8_t *testD = marshalling(&hm);
    for (size_t i = 0; i < get_size_of_hash_message(&hm); i++) {
        printf("%02x", testD[i]);
    }
    printf("\r\n");
}

void test2() {
    hash_message hm;
    unmarshalling_fill(test_cbor, 122, &hm);
    pretty_print_hash_message(&hm);
    hash_message hm2;
    unmarshalling_fill(test_cbor2, 243, &hm2);
    pretty_print_hash_message(&hm2);
}

int main() {
    test1();
    test2();
}
