/*****************************************************************************
 * npe_lib_xml.h — XML parsing and generation library
 *
 * Lua API exposed as: npe.xml.*
 *
 * Lua API:
 *   npe.xml.parse(xml)
 *   npe.xml.stringify(table)
 *   npe.xml.find(doc, xpath)
 *   npe.xml.attr(node, name)
 *****************************************************************************/

#ifndef NPE_LIB_XML_H
#define NPE_LIB_XML_H

#include "npe_types.h"
#include "npe_types.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct npe_vm npe_vm_t;

/* XML attribute */
typedef struct {
    char *name;
    char *value;
} npe_xml_attr_t;

/* XML node */
typedef struct npe_xml_node {

    char *name;
    char *text;

    npe_xml_attr_t *attributes;
    size_t attr_count;

    struct npe_xml_node **children;
    size_t child_count;

    struct npe_xml_node *parent;

} npe_xml_node_t;

/* XML document */
typedef struct {
    npe_xml_node_t *root;
} npe_xml_doc_t;

/* Parsing */
npe_error_t npe_xml_parse(const char *input,
                          size_t length,
                          npe_xml_doc_t **doc);

/* Serialize */
npe_error_t npe_xml_stringify(const npe_xml_doc_t *doc,
                              char **out,
                              size_t *len);

/* XPath-style search (simplified) */
npe_error_t npe_xml_find(npe_xml_node_t *node,
                         const char *path,
                         npe_xml_node_t ***results,
                         size_t *count);

/* Attribute lookup */
const char *npe_xml_attr(npe_xml_node_t *node, const char *name);

/* Free document */
void npe_xml_free(npe_xml_doc_t *doc);

/* Lua registration */
npe_error_t npe_lib_xml_register(npe_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif
