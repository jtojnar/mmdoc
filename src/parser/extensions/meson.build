src = files(
  'fenced-divs.cpp',
  'mmdoc-extensions.cpp',
)

cmark_mmdoc_extensions_lib = static_library(
  'cmark-mmdoc-extensions',
  src,
  include_directories: include_directories('cmark/src'),
  dependencies : [
    libcmark_gfm
  ],
)
