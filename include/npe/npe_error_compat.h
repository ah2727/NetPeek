#ifndef NPE_ERROR_COMPAT_H
#define NPE_ERROR_COMPAT_H

/*
 * Legacy error-name compatibility layer
 * Maps old NPE_ERR_* macros to current npe_error_t values
 *
 * This file must be included AFTER npe_types.h
 */

/* Memory */
#ifndef NPE_ERROR_MEMORY
#define NPE_ERROR_MEMORY NPE_ERROR_MEMORY
#endif

/* Parse */
#ifndef NPE_ERROR_PARSE
#define NPE_ERROR_PARSE NPE_ERROR_PARSE
#endif

/* Invalid argument */
#ifndef NPE_ERR_INVALID
#define NPE_ERR_INVALID NPE_ERROR_INVALID_ARG
#endif

/* Internal / generic failure */
#ifndef NPE_ERROR_GENERIC
#define NPE_ERROR_GENERIC NPE_ERROR_GENERIC
#endif

/* Optional extras (future-proofing) */
#ifndef NPE_ERROR_IO
#define NPE_ERROR_IO NPE_ERROR_IO
#endif

#ifndef NPE_ERR_TIMEOUT
#define NPE_ERR_TIMEOUT NPE_ERROR_TIMEOUT
#endif

#endif /* NPE_ERROR_COMPAT_H */