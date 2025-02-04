/* SPDX-License-Identifier: CC0-1.0 */
#include "asset.h"
#include "render.h"
#include "types.h"
#include <string.h>

int mmdoc_single(char *out, char *toc_path, char *project_name,
                 AnchorLocationArray toc_anchor_locations) {
  if (asset_write_to_dir_mmdoc_js(out) != 0 ||
      asset_write_to_dir_highlight_pack_js(out) != 0 ||
      asset_write_to_dir_mmdoc_css(out) != 0 ||
      asset_write_to_dir_a11y_light_css(out) != 0 ||
      asset_write_to_dir_a11y_dark_css(out) != 0) {
    return -1;
  }

  char index_path[2048];
  FILE *index_file;
  strcpy(index_path, out);
  strcat(index_path, "/index.html");
  index_file = fopen(index_path, "w");

  char *html_head =
      "<!doctype html>\n"
      "<html>\n"
      "  <head>\n"
      "    <meta charset='utf-8'>\n"
      "    <meta name='viewport' content='width=device-width, "
      "initial-scale=1.0'>\n"
      "    <link rel='icon' href='favicon.svg'>\n"
      "    <link href='mmdoc.css' rel='stylesheet' type='text/css'>\n"
      "    <link rel='stylesheet' href='a11y-light.css' "
      "media='(prefers-color-scheme: light)'>\n"
      "    <link rel='stylesheet' href='a11y-dark.css' "
      "media='(prefers-color-scheme: dark)'>\n"
      "    <script src='highlight.pack.js'></script>\n"
      "    <script>hljs.highlightAll()</script>\n"
      "    <script src='mmdoc.js'></script>\n"
      "    <script>\n"
      "      window.addEventListener('load', (event) => { \n"
      "        let codeElems = "
      "Array.from(document.querySelectorAll('code')).filter(function (elem) "
      "{return !elem.parentElement.classList.contains('heade'); });\n"
      "        codeElems.forEach(function (e) { e.classList.add('hljs'); });\n"
      "      });\n"
      "    </script>\n"
      "    <title>";
  fputs(html_head, index_file);
  fputs(project_name, index_file);
  char *html_head_end = "</title>\n"
                        "  </head>\n"
                        "  <body>\n"
                        "    <div class='nav-top-container'>\n";
  fputs(html_head_end, index_file);

  fputs("    <nav class='nav-top'>\n", index_file);
  fputs("      <button type='button' class='sidebar-toggle'>≡</button>",
        index_file);
  fputs(
      "    <button type='button' class='theme-toggle emoji'>🌘&#xFE0E;</button>",
      index_file);

  char *html_head_more = "    </nav>\n"
                         "    </div>\n";
  fputs(html_head_more, index_file);

  fputs("    <nav class='sidebar'>\n", index_file);
  AnchorLocation al;
  mmdoc_render_part(toc_path, index_file, RENDER_TYPE_SINGLE, &al,
                    toc_anchor_locations, NULL, NULL);
  fputs("    </nav>\n", index_file);
  fputs("    <section>\n", index_file);
  fputs("      <main>\n", index_file);

  for (int i = 0; i < toc_anchor_locations.used; i++) {
    AnchorLocationArray empty_anchor_locations;
    init_anchor_location_array(&empty_anchor_locations, 0);
    mmdoc_render_part(toc_anchor_locations.array[i].file_path, index_file,
                      RENDER_TYPE_SINGLE, &toc_anchor_locations.array[i],
                      empty_anchor_locations, NULL, NULL);
    free_anchor_location_array(&empty_anchor_locations);
  }

  char *html_foot = "      </main>\n"
                    "    </section>\n"
                    "  </body>\n"
                    "</html>\n";
  fputs(html_foot, index_file);
  fclose(index_file);
  return 0;
}
