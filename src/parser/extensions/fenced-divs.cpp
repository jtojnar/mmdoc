/* SPDX-License-Identifier: BSD-2-Clause */
#include <cmark-gfm-extension_api.h>
#include <html.h>
#include <inlines.h>
#include <parser.h>
#include <references.h>
#include <string.h>
#include <render.h>

// #include "ext_scanners.h"
// #include "strikethrough.h"
#include "fenced-divs.h"
#include "mmdoc-extensions.h"

cmark_node_type CMARK_NODE_FENCED_DIV;

// Local constants
static const char *TYPE_STRING = "fenced-div";

static const char *get_type_string(cmark_syntax_extension *extension, cmark_node *node) {
  return TYPE_STRING;
}

typedef struct {
  char *class_name;
} node_fenced_div;

static void free_node_fenced_div(cmark_mem *mem, void *data) {
  node_fenced_div *div = (node_fenced_div *)data;
  mem->free(div->class_name);
  mem->free(div);
}

char *cmark_gfm_extensions_get_fenced_div_class_name(cmark_node *node) {
  if (!node || node->type != CMARK_NODE_FENCED_DIV)
    return 0;

  return ((node_fenced_div *)node->as.opaque)->class_name;
}

int cmark_gfm_extensions_cet_fenced_div_class_name(cmark_node *node, char *class_name) {
  if (!node || node->type != CMARK_NODE_FENCED_DIV)
    return 0;

  ((node_fenced_div *)node->as.opaque)->class_name = class_name;
  return 1;
}

/*
static void try_inserting_table_header_paragraph(cmark_parser *parser,
                                                 cmark_node *parent_container,
                                                 unsigned char *parent_string,
                                                 int paragraph_offset) {
  cmark_node *paragraph;
  cmark_strbuf *paragraph_content;

  paragraph = cmark_node_new_with_mem(CMARK_NODE_PARAGRAPH, parser->mem);

  paragraph_content = unescape_pipes(parser->mem, parent_string, paragraph_offset);
  cmark_strbuf_trim(paragraph_content);
  cmark_node_set_string_content(paragraph, (char *) paragraph_content->ptr);
  cmark_strbuf_free(paragraph_content);
  parser->mem->free(paragraph_content);

  if (!cmark_node_insert_before(parent_container, paragraph)) {
    parser->mem->free(paragraph);
  }
}

static cmark_node *try_opening_table_header(cmark_syntax_extension *self,
                                            cmark_parser *parser,
                                            cmark_node *parent_container,
                                            unsigned char *input, int len) {
  cmark_node *table_header;
  table_row *header_row = NULL;
  table_row *marker_row = NULL;
  node_table_row *ntr;
  const char *parent_string;
  uint16_t i;

  if (!scan_table_start(input, len, cmark_parser_get_first_nonspace(parser))) {
    return parent_container;
  }

  // Since scan_table_start was successful, we must have a marker row.
  marker_row = row_from_string(self, parser,
                               input + cmark_parser_get_first_nonspace(parser),
                               len - cmark_parser_get_first_nonspace(parser));
  assert(marker_row);

  cmark_arena_push();

  // Check for a matching header row. We call `row_from_string` with the entire
  // (potentially long) parent container as input, but this should be safe since
  // `row_from_string` bails out early if it does not find a row.
  parent_string = cmark_node_get_string_content(parent_container);
  header_row = row_from_string(self, parser, (unsigned char *)parent_string,
                               (int)strlen(parent_string));
  if (!header_row || header_row->n_columns != marker_row->n_columns) {
    free_table_row(parser->mem, marker_row);
    free_table_row(parser->mem, header_row);
    cmark_arena_pop();
    return parent_container;
  }

  if (cmark_arena_pop()) {
    marker_row = row_from_string(
        self, parser, input + cmark_parser_get_first_nonspace(parser),
        len - cmark_parser_get_first_nonspace(parser));
    header_row = row_from_string(self, parser, (unsigned char *)parent_string,
                                 (int)strlen(parent_string));
  }

  if (!cmark_node_set_type(parent_container, CMARK_NODE_FENCED_DIV)) {
    free_table_row(parser->mem, header_row);
    free_table_row(parser->mem, marker_row);
    return parent_container;
  }

  if (header_row->paragraph_offset) {
    try_inserting_table_header_paragraph(parser, parent_container, (unsigned char *)parent_string,
                                         header_row->paragraph_offset);
  }

  cmark_node_set_syntax_extension(parent_container, self);
  parent_container->as.opaque = parser->mem->calloc(1, sizeof(node_fenced_div));
  set_n_table_columns(parent_container, header_row->n_columns);

  uint8_t *alignments =
      (uint8_t *)parser->mem->calloc(header_row->n_columns, sizeof(uint8_t));
  cmark_llist *it = marker_row->cells;
  for (i = 0; it; it = it->next, ++i) {
    node_cell *node = (node_cell *)it->data;
    bool left = node->buf->ptr[0] == ':', right = node->buf->ptr[node->buf->size - 1] == ':';

    if (left && right)
      alignments[i] = 'c';
    else if (left)
      alignments[i] = 'l';
    else if (right)
      alignments[i] = 'r';
  }
  set_fenced_div_class_name(parent_container, alignments);

  table_header =
      cmark_parser_add_child(parser, parent_container, CMARK_NODE_TABLE_ROW,
                             parent_container->start_column);
  cmark_node_set_syntax_extension(table_header, self);
  table_header->end_column = parent_container->start_column + (int)strlen(parent_string) - 2;
  table_header->start_line = table_header->end_line = parent_container->start_line;

  table_header->as.opaque = ntr = (node_table_row *)parser->mem->calloc(1, sizeof(node_table_row));
  ntr->is_header = true;

  {
    cmark_llist *tmp;

    for (tmp = header_row->cells; tmp; tmp = tmp->next) {
      node_cell *cell = (node_cell *) tmp->data;
      cmark_node *header_cell = cmark_parser_add_child(parser, table_header,
          CMARK_NODE_TABLE_CELL, parent_container->start_column + cell->start_offset);
      header_cell->start_line = header_cell->end_line = parent_container->start_line;
      header_cell->internal_offset = cell->internal_offset;
      header_cell->end_column = parent_container->start_column + cell->end_offset;
      cmark_node_set_string_content(header_cell, (char *) cell->buf->ptr);
      cmark_node_set_syntax_extension(header_cell, self);
    }
  }

  cmark_parser_advance_offset(
      parser, (char *)input,
      (int)strlen((char *)input) - 1 - cmark_parser_get_offset(parser), false);

  free_table_row(parser->mem, header_row);
  free_table_row(parser->mem, marker_row);
  return parent_container;
}

static cmark_node *try_opening_table_row(cmark_syntax_extension *self,
                                         cmark_parser *parser,
                                         cmark_node *parent_container,
                                         unsigned char *input, int len) {
  cmark_node *table_row_block;
  table_row *row;

  if (cmark_parser_is_blank(parser))
    return NULL;

  table_row_block =
      cmark_parser_add_child(parser, parent_container, CMARK_NODE_TABLE_ROW,
                             parent_container->start_column);
  cmark_node_set_syntax_extension(table_row_block, self);
  table_row_block->end_column = parent_container->end_column;
  table_row_block->as.opaque = parser->mem->calloc(1, sizeof(node_table_row));

  row = row_from_string(self, parser, input + cmark_parser_get_first_nonspace(parser),
      len - cmark_parser_get_first_nonspace(parser));

  {
    cmark_llist *tmp;
    int i, table_columns = get_n_table_columns(parent_container);

    for (tmp = row->cells, i = 0; tmp && i < table_columns; tmp = tmp->next, ++i) {
      node_cell *cell = (node_cell *) tmp->data;
      cmark_node *node = cmark_parser_add_child(parser, table_row_block,
          CMARK_NODE_TABLE_CELL, parent_container->start_column + cell->start_offset);
      node->internal_offset = cell->internal_offset;
      node->end_column = parent_container->start_column + cell->end_offset;
      cmark_node_set_string_content(node, (char *) cell->buf->ptr);
      cmark_node_set_syntax_extension(node, self);
    }

    for (; i < table_columns; ++i) {
      cmark_node *node = cmark_parser_add_child(
          parser, table_row_block, CMARK_NODE_TABLE_CELL, 0);
      cmark_node_set_syntax_extension(node, self);
    }
  }

  free_table_row(parser->mem, row);

  cmark_parser_advance_offset(parser, (char *)input,
                              len - 1 - cmark_parser_get_offset(parser), false);

  return table_row_block;
}
*/

static cmark_node *try_opening_table_block(cmark_syntax_extension *self,
                                           int indented, cmark_parser *parser,
                                           cmark_node *parent_container,
                                           unsigned char *input, int len) {
  cmark_node_type parent_type = cmark_node_get_type(parent_container);

  if (!indented && parent_type == CMARK_NODE_PARAGRAPH) {
    return try_opening_table_header(self, parser, parent_container, input, len);
  } else if (!indented && parent_type == CMARK_NODE_FENCED_DIV) {
    return try_opening_table_row(self, parser, parent_container, input, len);
  }

  return NULL;
}

static int matches(cmark_syntax_extension *self, cmark_parser *parser,
                   unsigned char *input, int len,
                   cmark_node *parent_container) {
  int res = 0;

  if (cmark_node_get_type(parent_container) == CMARK_NODE_FENCED_DIV) {
    cmark_arena_push();
    table_row *new_row = row_from_string(
        self, parser, input + cmark_parser_get_first_nonspace(parser),
        len - cmark_parser_get_first_nonspace(parser));
    if (new_row && new_row->n_columns)
      res = 1;
    free_table_row(parser->mem, new_row);
    cmark_arena_pop();
  }

  return res;
}

static int can_contain(cmark_syntax_extension *extension, cmark_node *node,
                       cmark_node_type child_type) {
  if (node->type == CMARK_NODE_FENCED_DIV) {
    return true;
  }
  return false;
}

/*

static void commonmark_render(cmark_syntax_extension *extension,
                              cmark_renderer *renderer, cmark_node *node,
                              cmark_event_type ev_type, int options) {
  bool entering = (ev_type == CMARK_EVENT_ENTER);

  if (node->type == CMARK_NODE_FENCED_DIV) {
    renderer->blankline(renderer);
  } else if (node->type == CMARK_NODE_TABLE_ROW) {
    if (entering) {
      renderer->cr(renderer);
      renderer->out(renderer, node, "|", false, LITERAL);
    }
  } else if (node->type == CMARK_NODE_TABLE_CELL) {
    if (entering) {
      renderer->out(renderer, node, " ", false, LITERAL);
    } else {
      renderer->out(renderer, node, " |", false, LITERAL);
      if (((node_table_row *)node->parent->as.opaque)->is_header &&
          !node->next) {
        int i;
        uint8_t *alignments = get_fenced_div_class_name(node->parent->parent);
        uint16_t n_cols =
            ((node_fenced_div *)node->parent->parent->as.opaque)->n_columns;
        renderer->cr(renderer);
        renderer->out(renderer, node, "|", false, LITERAL);
        for (i = 0; i < n_cols; i++) {
          switch (alignments[i]) {
          case 0:   renderer->out(renderer, node, " --- |", false, LITERAL); break;
          case 'l': renderer->out(renderer, node, " :-- |", false, LITERAL); break;
          case 'c': renderer->out(renderer, node, " :-: |", false, LITERAL); break;
          case 'r': renderer->out(renderer, node, " --: |", false, LITERAL); break;
          }
        }
        renderer->cr(renderer);
      }
    }
  } else {
    assert(false);
  }
}

static void latex_render(cmark_syntax_extension *extension,
                         cmark_renderer *renderer, cmark_node *node,
                         cmark_event_type ev_type, int options) {
  bool entering = (ev_type == CMARK_EVENT_ENTER);

  if (node->type == CMARK_NODE_FENCED_DIV) {
    if (entering) {
      int i;
      uint16_t n_cols;
      uint8_t *alignments = get_fenced_div_class_name(node);

      renderer->cr(renderer);
      renderer->out(renderer, node, "\\begin{table}", false, LITERAL);
      renderer->cr(renderer);
      renderer->out(renderer, node, "\\begin{tabular}{", false, LITERAL);

      n_cols = ((node_fenced_div *)node->as.opaque)->n_columns;
      for (i = 0; i < n_cols; i++) {
        switch(alignments[i]) {
        case 0:
        case 'l':
          renderer->out(renderer, node, "l", false, LITERAL);
          break;
        case 'c':
          renderer->out(renderer, node, "c", false, LITERAL);
          break;
        case 'r':
          renderer->out(renderer, node, "r", false, LITERAL);
          break;
        }
      }
      renderer->out(renderer, node, "}", false, LITERAL);
      renderer->cr(renderer);
    } else {
      renderer->out(renderer, node, "\\end{tabular}", false, LITERAL);
      renderer->cr(renderer);
      renderer->out(renderer, node, "\\end{table}", false, LITERAL);
      renderer->cr(renderer);
    }
  } else if (node->type == CMARK_NODE_TABLE_ROW) {
    if (!entering) {
      renderer->cr(renderer);
    }
  } else if (node->type == CMARK_NODE_TABLE_CELL) {
    if (!entering) {
      if (node->next) {
        renderer->out(renderer, node, " & ", false, LITERAL);
      } else {
        renderer->out(renderer, node, " \\\\", false, LITERAL);
      }
    }
  } else {
    assert(false);
  }
}

static const char *xml_attr(cmark_syntax_extension *extension,
                            cmark_node *node) {
  if (node->type == CMARK_NODE_TABLE_CELL) {
    if (cmark_gfm_extensions_get_table_row_is_header(node->parent)) {
      uint8_t *alignments = get_fenced_div_class_name(node->parent->parent);
      int i = 0;
      cmark_node *n;
      for (n = node->parent->first_child; n; n = n->next, ++i)
        if (n == node)
          break;
      switch (alignments[i]) {
      case 'l': return " align=\"left\"";
      case 'c': return " align=\"center\"";
      case 'r': return " align=\"right\"";
      }
    }
  }

  return NULL;
}

static void man_render(cmark_syntax_extension *extension,
                       cmark_renderer *renderer, cmark_node *node,
                       cmark_event_type ev_type, int options) {
  bool entering = (ev_type == CMARK_EVENT_ENTER);

  if (node->type == CMARK_NODE_FENCED_DIV) {
    if (entering) {
      int i;
      uint16_t n_cols;
      uint8_t *alignments = get_fenced_div_class_name(node);

      renderer->cr(renderer);
      renderer->out(renderer, node, ".TS", false, LITERAL);
      renderer->cr(renderer);
      renderer->out(renderer, node, "tab(@);", false, LITERAL);
      renderer->cr(renderer);

      n_cols = ((node_fenced_div *)node->as.opaque)->n_columns;

      for (i = 0; i < n_cols; i++) {
        switch (alignments[i]) {
        case 'l':
          renderer->out(renderer, node, "l", false, LITERAL);
          break;
        case 0:
        case 'c':
          renderer->out(renderer, node, "c", false, LITERAL);
          break;
        case 'r':
          renderer->out(renderer, node, "r", false, LITERAL);
          break;
        }
      }

      if (n_cols) {
        renderer->out(renderer, node, ".", false, LITERAL);
        renderer->cr(renderer);
      }
    } else {
      renderer->out(renderer, node, ".TE", false, LITERAL);
      renderer->cr(renderer);
    }
  } else if (node->type == CMARK_NODE_TABLE_ROW) {
    if (!entering) {
      renderer->cr(renderer);
    }
  } else if (node->type == CMARK_NODE_TABLE_CELL) {
    if (!entering && node->next) {
      renderer->out(renderer, node, "@", false, LITERAL);
    }
  } else {
    assert(false);
  }
}

static void html_table_add_align(cmark_strbuf* html, const char* align, int options) {
  if (options & CMARK_OPT_TABLE_PREFER_STYLE_ATTRIBUTES) {
    cmark_strbuf_puts(html, " style=\"text-align: ");
    cmark_strbuf_puts(html, align);
    cmark_strbuf_puts(html, "\"");
  } else {
    cmark_strbuf_puts(html, " align=\"");
    cmark_strbuf_puts(html, align);
    cmark_strbuf_puts(html, "\"");
  }
}

struct html_table_state {
  unsigned need_closing_table_body : 1;
  unsigned in_table_header : 1;
};

static void html_render(cmark_syntax_extension *extension,
                        cmark_html_renderer *renderer, cmark_node *node,
                        cmark_event_type ev_type, int options) {
  bool entering = (ev_type == CMARK_EVENT_ENTER);
  cmark_strbuf *html = renderer->html;
  cmark_node *n;

  // XXX: we just monopolise renderer->opaque.
  struct html_table_state *table_state =
      (struct html_table_state *)&renderer->opaque;

  if (node->type == CMARK_NODE_FENCED_DIV) {
    if (entering) {
      cmark_html_render_cr(html);
      cmark_strbuf_puts(html, "<table");
      cmark_html_render_sourcepos(node, html, options);
      cmark_strbuf_putc(html, '>');
      table_state->need_closing_table_body = false;
    } else {
      if (table_state->need_closing_table_body) {
        cmark_html_render_cr(html);
        cmark_strbuf_puts(html, "</tbody>");
        cmark_html_render_cr(html);
      }
      table_state->need_closing_table_body = false;
      cmark_html_render_cr(html);
      cmark_strbuf_puts(html, "</table>");
      cmark_html_render_cr(html);
    }
  } else if (node->type == CMARK_NODE_TABLE_ROW) {
    if (entering) {
      cmark_html_render_cr(html);
      if (((node_table_row *)node->as.opaque)->is_header) {
        table_state->in_table_header = 1;
        cmark_strbuf_puts(html, "<thead>");
        cmark_html_render_cr(html);
      } else if (!table_state->need_closing_table_body) {
        cmark_strbuf_puts(html, "<tbody>");
        cmark_html_render_cr(html);
        table_state->need_closing_table_body = 1;
      }
      cmark_strbuf_puts(html, "<tr");
      cmark_html_render_sourcepos(node, html, options);
      cmark_strbuf_putc(html, '>');
    } else {
      cmark_html_render_cr(html);
      cmark_strbuf_puts(html, "</tr>");
      if (((node_table_row *)node->as.opaque)->is_header) {
        cmark_html_render_cr(html);
        cmark_strbuf_puts(html, "</thead>");
        table_state->in_table_header = false;
      }
    }
  } else if (node->type == CMARK_NODE_TABLE_CELL) {
    uint8_t *alignments = get_fenced_div_class_name(node->parent->parent);
    if (entering) {
      cmark_html_render_cr(html);
      if (table_state->in_table_header) {
        cmark_strbuf_puts(html, "<th");
      } else {
        cmark_strbuf_puts(html, "<td");
      }

      int i = 0;
      for (n = node->parent->first_child; n; n = n->next, ++i)
        if (n == node)
          break;

      switch (alignments[i]) {
      case 'l': html_table_add_align(html, "left", options); break;
      case 'c': html_table_add_align(html, "center", options); break;
      case 'r': html_table_add_align(html, "right", options); break;
      }

      cmark_html_render_sourcepos(node, html, options);
      cmark_strbuf_putc(html, '>');
    } else {
      if (table_state->in_table_header) {
        cmark_strbuf_puts(html, "</th>");
      } else {
        cmark_strbuf_puts(html, "</td>");
      }
    }
  } else {
    assert(false);
  }
}
*/
static void opaque_alloc(cmark_syntax_extension *self, cmark_mem *mem, cmark_node *node) {
  if (node->type == CMARK_NODE_FENCED_DIV) {
    node->as.opaque = mem->calloc(1, sizeof(node_fenced_div));
  }
}

static void opaque_free(cmark_syntax_extension *self, cmark_mem *mem, cmark_node *node) {
  if (node->type == CMARK_NODE_FENCED_DIV) {
    free_node_fenced_div(mem, node->as.opaque);
  }
}

static int escape(cmark_syntax_extension *self, cmark_node *node, int c) {
  return
    node->type != CMARK_NODE_FENCED_DIV &&
    c == '|';
}

cmark_syntax_extension *create_fenced_divs_extension(void) {
  cmark_syntax_extension *self = cmark_syntax_extension_new("fenced-divs");

  cmark_syntax_extension_set_match_block_func(self, matches);
  cmark_syntax_extension_set_open_block_func(self, try_opening_table_block);
  cmark_syntax_extension_set_get_type_string_func(self, get_type_string);
  cmark_syntax_extension_set_can_contain_func(self, can_contain);
  // cmark_syntax_extension_set_commonmark_render_func(self, commonmark_render);
  // cmark_syntax_extension_set_plaintext_render_func(self, commonmark_render);
  // cmark_syntax_extension_set_latex_render_func(self, latex_render);
  // cmark_syntax_extension_set_xml_attr_func(self, xml_attr);
  // cmark_syntax_extension_set_man_render_func(self, man_render);
  // cmark_syntax_extension_set_html_render_func(self, html_render);
  cmark_syntax_extension_set_opaque_alloc_func(self, opaque_alloc);
  cmark_syntax_extension_set_opaque_free_func(self, opaque_free);
  // cmark_syntax_extension_set_commonmark_escape_func(self, escape);
  CMARK_NODE_FENCED_DIV = cmark_syntax_extension_add_node(0);

  return self;
}
