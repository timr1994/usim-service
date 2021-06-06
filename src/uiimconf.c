/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file uiimconf.c
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-03-23
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "uiimconf.h"

TPM2_ALG_ID get_alg_id(char *str) {
    if (0 == strcmp((char *) str, "TPM2_ALG_ERROR")) {
        return TPM2_ALG_ERROR;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_RSA")) {
        return TPM2_ALG_RSA;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_TDES")) {
        return TPM2_ALG_TDES;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA")) {
        return TPM2_ALG_SHA;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA1")) {
        return TPM2_ALG_SHA1;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_HMAC")) {
        return TPM2_ALG_HMAC;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_AES")) {
        return TPM2_ALG_AES;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_MGF1")) {
        return TPM2_ALG_MGF1;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_KEYEDHASH")) {
        return TPM2_ALG_KEYEDHASH;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_XOR")) {
        return TPM2_ALG_XOR;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA256")) {
        return TPM2_ALG_SHA256;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA384")) {
        return TPM2_ALG_SHA384;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA512")) {
        return TPM2_ALG_SHA512;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_NULL")) {
        return TPM2_ALG_NULL;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SM3_256")) {
        return TPM2_ALG_SM3_256;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SM4")) {
        return TPM2_ALG_SM4;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_RSASSA")) {
        return TPM2_ALG_RSASSA;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_RSAES")) {
        return TPM2_ALG_RSAES;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_RSAPSS")) {
        return TPM2_ALG_RSAPSS;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_OAEP")) {
        return TPM2_ALG_OAEP;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_ECDSA")) {
        return TPM2_ALG_ECDSA;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_ECDH")) {
        return TPM2_ALG_ECDH;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_ECDAA")) {
        return TPM2_ALG_ECDAA;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SM2")) {
        return TPM2_ALG_SM2;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_ECSCHNORR")) {
        return TPM2_ALG_ECSCHNORR;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_ECMQV")) {
        return TPM2_ALG_ECMQV;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_KDF1_SP800_56A")) {
        return TPM2_ALG_KDF1_SP800_56A;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_KDF2")) {
        return TPM2_ALG_KDF2;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_KDF1_SP800_108")) {
        return TPM2_ALG_KDF1_SP800_108;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_ECC")) {
        return TPM2_ALG_ECC;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SYMCIPHER")) {
        return TPM2_ALG_SYMCIPHER;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_CAMELLIA")) {
        return TPM2_ALG_CAMELLIA;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_CMAC")) {
        return TPM2_ALG_CMAC;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_CTR")) {
        return TPM2_ALG_CTR;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA3_256")) {
        return TPM2_ALG_SHA3_256;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA3_384")) {
        return TPM2_ALG_SHA3_384;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_SHA3_512")) {
        return TPM2_ALG_SHA3_512;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_OFB")) {
        return TPM2_ALG_OFB;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_CBC")) {
        return TPM2_ALG_CBC;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_CFB")) {
        return TPM2_ALG_CFB;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_ECB")) {
        return TPM2_ALG_ECB;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_FIRST")) {
        return TPM2_ALG_FIRST;
    } else if (0 == strcmp((char *) str, "TPM2_ALG_LAST")) {
        return TPM2_ALG_LAST;
    }
}

/**
 * @brief Help function to parse listen address
 * 
 * @param parser YAML-Parser on right postion
 * @return 1 on error, 0 on sucess
 */
int parse_listen_address(yaml_parser_t *parser, uiimconf *conf) {
    yaml_event_t event;
    if (!yaml_parser_parse(parser, &event)) {

    }
    in_addr_t tmp;
    if (INADDR_NONE == (tmp = inet_addr((char *) event.data.scalar.value))) {
        return 1;
    } else {
        conf->ADDRESS = tmp;
    }

    yaml_event_delete(&event);

    return 0;
}

/**
 * @brief Help function to parse listen port
 * 
 * @param parser YAML-Parser on right postion
 * @return 1 on error, 0 on sucess
 */
int parse_listen_port(yaml_parser_t *parser, uiimconf *conf) {
    yaml_event_t event;
    if (!yaml_parser_parse(parser, &event)) {

    }
    conf->PORT = atoi((char *) event.data.scalar.value);

    yaml_event_delete(&event);

    return 0;
}

/**
 * @brief Help function to parse output path
 * 
 * @param parser YAML-Parser on right postion
 * @return 1 on error, 0 on sucess
 */
int parse_output_path(yaml_parser_t *parser, uiimconf *conf) {
    yaml_event_t event;
    if (!yaml_parser_parse(parser, &event)) {

    }
    conf->LOG_OUTPUT_PATH = (char *) malloc(strlen((char *) event.data.scalar.value) + 1);
    strcpy(conf->LOG_OUTPUT_PATH, (char *) event.data.scalar.value);

    yaml_event_delete(&event);

    return 0;
}

/**
 * @brief Help function to parse selected hashs
 * 
 * @param parser YAML-Parser on right postion
 * @return 1 on error, 0 on sucess
 */
int parse_selected_hashs(yaml_parser_t *parser, uiimconf *conf) {
    yaml_event_t event;
    int done = 0;
    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {

        }
        if (event.type == YAML_SCALAR_EVENT) {
            conf->alg_ids = realloc(conf->alg_ids, ((conf->alg_ids_len+1) * sizeof (TPM2_ALG_ID)));
            conf->alg_ids[conf->alg_ids_len] = get_alg_id(event.data.scalar.value);
            conf->alg_ids_len++;
        }
        if (event.type == YAML_SEQUENCE_END_EVENT) {
            done = 1;
        }
        yaml_event_delete(&event);
    }




    return 0;
}

/**
 * @brief Help function to parse output typ
 * 
 * @param parser YAML-Parser on right postion
 * @return 1 on error, 0 on sucess
 */
int parse_output_typ(yaml_parser_t *parser, uiimconf *conf) {
    yaml_event_t event;
    if (!yaml_parser_parse(parser, &event)) {
    }
    if (0 == strcmp("CBOR", (char *) event.data.scalar.value)) {
        conf->logtyp = CBOR;
    } else if (0 == strcmp("CBORHex", (char *) event.data.scalar.value)) {
        conf->logtyp = CBORHex;
    } else if (0 == strcmp("HR", (char *) event.data.scalar.value)) {
        conf->logtyp = HR;
    }

    return 0;
}

uiimconf * parse_yaml_conf(FILE *fh) {
    uiimconf *conf = malloc(sizeof (uiimconf));
    conf->ADDRESS = INADDR_LOOPBACK;
    conf->PORT = 5001;
    conf->logtyp = CBOR;
    conf->alg_ids_len = 0;
    conf->alg_ids = NULL;
    conf->LOG_OUTPUT_PATH = ".";
    yaml_parser_t parser;
    yaml_event_t event;
    int done = 0;
    /* Initialize parser */
    if (!yaml_parser_initialize(&parser))
        fputs("Failed to initialize parser!\n", stderr);
    if (fh == NULL)
        fputs("Failed to open file!\n", stderr);

    /* Set input file */
    yaml_parser_set_input_file(&parser, fh);
    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            break;
        }

        done = (event.type == YAML_STREAM_END_EVENT);
        switch (event.type) {
            case YAML_NO_EVENT: puts("No event!");
                break;
                /* Stream start/end */
            case YAML_STREAM_START_EVENT:
                break;
            case YAML_STREAM_END_EVENT:
                done = 1;
                break;
                /* Block delimeters */
            case YAML_DOCUMENT_START_EVENT:
                break;
            case YAML_DOCUMENT_END_EVENT:
                break;
            case YAML_SEQUENCE_START_EVENT:
                break;
            case YAML_SEQUENCE_END_EVENT:
                break;
            case YAML_MAPPING_START_EVENT:
                break;
            case YAML_MAPPING_END_EVENT:
                break;
                /* Data */
            case YAML_ALIAS_EVENT:
                break;
            case YAML_SCALAR_EVENT:
                if (0 == strcmp((char *) event.data.scalar.value, "listen_address")) {
                    parse_listen_address(&parser, conf);
                } else if (0 == strcmp((char *) event.data.scalar.value, "listen_port")) {
                    parse_listen_port(&parser, conf);
                } else if (0 == strcmp((char *) event.data.scalar.value, "output_path")) {
                    parse_output_path(&parser, conf);
                } else if (0 == strcmp((char *) event.data.scalar.value, "selected_hashs")) {
                    parse_selected_hashs(&parser, conf);
                } else if (0 == strcmp((char *) event.data.scalar.value, "output_typ")) {

                    parse_output_typ(&parser, conf);
                }
                break;
        }
        yaml_event_delete(&event);

    }
    /* Cleanup */
    yaml_parser_delete(&parser);
    fclose(fh);
    return conf;
}

