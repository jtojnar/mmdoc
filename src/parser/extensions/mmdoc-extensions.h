#pragma once

#include "cmark-gfm-extension_api.h"
#include "cmark-gfm-extensions_export.h"
#include <stdint.h>

CMARK_GFM_EXTENSIONS_EXPORT
void cmark_mmdoc_extensions_ensure_registered(void);

/** Gets the class name for the fenced div.
 */
CMARK_GFM_EXTENSIONS_EXPORT
const char *cmark_mmdoc_extensions_fenced_div_get_class_name(cmark_node *node);

/** Sets the class name for the fenced div, returning 1 on success and 0 on error.
 */
CMARK_GFM_EXTENSIONS_EXPORT
int cmark_mmdoc_extensions_fenced_div_set_class_name(cmark_node *node, char *class_name);
