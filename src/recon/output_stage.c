#include "recon/output.h"
#include "recon/output_base.h"

#include <string.h>

static const char *legacy_format_from_cfg(const np_config_t *cfg)
{
    switch (cfg->output_fmt)
    {
    case NP_OUTPUT_JSON: return "json";
    case NP_OUTPUT_XML: return "xml";
    case NP_OUTPUT_HTML: return "html";
    case NP_OUTPUT_CSV: return "csv";
    case NP_OUTPUT_GREPPABLE: return "text";
    case NP_OUTPUT_PLAIN:
    default:
        return "text";
    }
}

np_status_t np_recon_apply_legacy_output_mapping(np_config_t *cfg)
{
    if (!cfg)
        return NP_ERR_ARGS;

    if (cfg->recon_output_format && cfg->recon_output_format[0])
        return NP_OK;

    switch (cfg->output_fmt)
    {
    case NP_OUTPUT_JSON:
        cfg->recon_output_format = "json";
        break;
    case NP_OUTPUT_XML:
        cfg->recon_output_format = "xml";
        break;
    case NP_OUTPUT_HTML:
        cfg->recon_output_format = "html";
        break;
    case NP_OUTPUT_CSV:
        cfg->recon_output_format = "csv";
        break;
    case NP_OUTPUT_GREPPABLE:
    case NP_OUTPUT_PLAIN:
    default:
        cfg->recon_output_format = "text";
        break;
    }

    return NP_OK;
}

static const char *format_from_cfg(const np_config_t *cfg)
{
    if (!cfg)
        return "text";

    if (cfg->recon_output_format && cfg->recon_output_format[0])
        return cfg->recon_output_format;

    if (cfg->output_file && cfg->output_file[0])
        return np_format_from_extension(cfg->output_file);

    if (cfg->recon_style == NP_RECON_STYLE_JSON)
        return "json";

    if (cfg->recon_style == NP_RECON_STYLE_REPORT)
        return "html";

    return legacy_format_from_cfg(cfg);
}

np_status_t np_output_stage_run(np_recon_context_t *ctx)
{
    if (!ctx || !ctx->cfg)
        return NP_ERR_ARGS;

    np_status_t rc = np_recon_output_register_builtins();
    if (rc != NP_OK)
        return rc;

    np_output_config_t ocfg = {
        .format = format_from_cfg(ctx->cfg),
        .path = ctx->cfg->output_file,
        .pretty = ctx->cfg->pretty_output,
        .include_evidence = ctx->cfg->show_evidence,
        .color = !ctx->cfg->recon_no_color,
        .compact = ctx->cfg->recon_compact || ctx->cfg->recon_style == NP_RECON_STYLE_COMPACT,
        .summary_only = ctx->cfg->recon_summary_only,
        .verbose = ctx->cfg->recon_verbose_detail || ctx->cfg->verbose,
        .recon_cli_mode = ctx->cfg->recon_cli_mode,
        .style = ctx->cfg->recon_style,
    };

    np_output_doc_t doc;
    np_output_doc_init(&doc);

    rc = np_output_doc_from_recon(ctx, &doc);
    if (rc != NP_OK)
    {
        np_output_doc_free(&doc);
        return rc;
    }

    const np_output_module_t *mod = np_output_find(ocfg.format);
    if (!mod)
    {
        np_output_doc_free(&doc);
        return NP_ERR_ARGS;
    }

    rc = mod->emit(ctx, &ocfg);
    np_output_doc_free(&doc);
    return rc;
}
