src = [
  'asset.c',
  'epub.c',
  'man.c',
  'mkdir_p.c',
  'multi.c',
  'parse.c',
  'render.c',
  'single.c',
  'types.c',
]

subdir('parser/extensions')

shared_lib = static_library(
  'shared',
  src,
  dependencies : [
    asset_dep, libcmark_gfm, libfastjson, libzip,
  ],
  link_with : [
    cmark_mmdoc_extensions_lib,
  ],
)

mmdoc_conf = configuration_data()
mmdoc_conf.set_quoted('MMDOC_VERSION', meson.project_version())

configure_file(input : 'mmdocconfig.h.in',
  output : 'mmdocconfig.h',
  configuration : mmdoc_conf)


mmdoc = executable('mmdoc',
                     [ 'mmdoc.c' ],
                     install : true,
                     pie : true,
                     link_with : [ shared_lib ])
