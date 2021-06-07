/* SPDX-License-Identifier: BSD-2-Clause */
#pragma once

#include "mmdoc-extensions.h"

extern cmark_node_type CMARK_NODE_FENCED_DIV;

cmark_syntax_extension *create_fenced_divs_extension(void);
