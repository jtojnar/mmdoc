#include "mmdoc-extensions.h"
#include "fenced-divs.h"
#include "registry.h"
#include "plugin.h"

static int cmark_mmdoc_extensions_registration(cmark_plugin *plugin) {
  cmark_plugin_register_syntax_extension(plugin, create_fenced_divs_extension());
  return 1;
}

extern "C" {

void cmark_mmdoc_extensions_ensure_registered(void) {
  static int registered = 0;

  if (!registered) {
    cmark_register_plugin(cmark_mmdoc_extensions_registration);
    registered = 1;
  }
}

}
