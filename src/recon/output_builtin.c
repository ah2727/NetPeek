#include "recon/output.h"

extern const np_output_module_t np_recon_output_text_module;
extern const np_output_module_t np_recon_output_json_module;
extern const np_output_module_t np_recon_output_csv_module;
extern const np_output_module_t np_recon_output_html_module;
extern const np_output_module_t np_recon_output_md_module;
extern const np_output_module_t np_recon_output_xml_module;
extern const np_output_module_t np_recon_output_sarif_module;
extern const np_output_module_t np_recon_output_diff_module;

np_status_t np_recon_output_register_builtins(void)
{
    np_status_t rc = np_output_register(&np_recon_output_text_module);
    if (rc != NP_OK)
        return rc;

    rc = np_output_register(&np_recon_output_html_module);
    if (rc != NP_OK)
        return rc;

    rc = np_output_register(&np_recon_output_csv_module);
    if (rc != NP_OK)
        return rc;

    rc = np_output_register(&np_recon_output_md_module);
    if (rc != NP_OK)
        return rc;

    rc = np_output_register(&np_recon_output_xml_module);
    if (rc != NP_OK)
        return rc;

    rc = np_output_register(&np_recon_output_sarif_module);
    if (rc != NP_OK)
        return rc;

    rc = np_output_register(&np_recon_output_diff_module);
    if (rc != NP_OK)
        return rc;

    return np_output_register(&np_recon_output_json_module);
}
