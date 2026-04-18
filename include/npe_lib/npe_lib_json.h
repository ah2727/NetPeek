/*****************************************************************************
 * npe_lib_json.h — JSON encoding/decoding library
 *
 * Provides high-performance JSON parsing and generation for NPE scripts.
 * Lua API exposed as: npe.json.*
 *
 * Lua API:
 *   npe.json.decode(str)
 *   npe.json.encode(value, options?)
 *   npe.json.pretty(value)
 *   npe.json.validate(str)
 *****************************************************************************/

#ifndef NPE_LIB_JSON_H
#define NPE_LIB_JSON_H

#include "npe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct npe_vm npe_vm_t;

/* JSON value types */
typedef enum {
    NPE_JSON_NULL,
    NPE_JSON_BOOL,
    NPE_JSON_NUMBER,
    NPE_JSON_STRING,
    NPE_JSON_ARRAY,
    NPE_JSON_OBJECT
} npe_json_type_t;

/* JSON value container */
typedef struct npe_json_value {
    npe_json_type_t type;

    union {
        double number;
        bool boolean;
        char *string;

        struct {
            struct npe_json_value **items;
            size_t count;
        } array;

        struct {
            char **keys;
            struct npe_json_value **values;
            size_t count;
        } object;
    };

} npe_json_value_t;

/* Encoding options */
typedef struct {
    bool pretty;
    bool escape_unicode;
    int indent;
} npe_json_encode_opts_t;

/* Parsing */
npe_error_t npe_json_parse(const char *input,
                           size_t length,
                           npe_json_value_t **out);

/* Serialization */
npe_error_t npe_json_stringify(const npe_json_value_t *value,
                               const npe_json_encode_opts_t *opts,
                               char **out,
                               size_t *out_len);

/* Validation */
bool npe_json_validate(const char *input, size_t length);

/* Free value */
void npe_json_free(npe_json_value_t *value);

/* Lua registration */
npe_error_t npe_lib_json_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif
