/* SPDX-License-Identifier: CC0-1.0 */
#include "epub.h"
#include "man.h"
#include "mkdir_p.h"
#include "multi.h"
#include "render.h"
#include "single.h"
#include "types.h"
#include <dirent.h>
#include <errno.h>
#include <mmdocconfig.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int errno;

void print_usage() {
  printf("mmdoc version %s - minimal markdown documentation\n", MMDOC_VERSION);
  printf("\n");
  printf("mmdoc PROJECT_NAME SRC OUT\n");
  printf("\n");
  printf("options:\n");
  printf("-h, --help                show help\n");
  printf("\n");
  printf("PROJECT_NAME is the name of the project the documentation is "
         "generated for.\n");
  printf("\n");
  printf("SRC a directory containing Markdown files; a file called toc.md at "
         "the top level\n");
  printf("is required.\n");
  printf("\n");
  printf("OUT a directory where the documentation is written to.\n");
}

int ends_with(const char *str, size_t str_len, const char *suffix,
              size_t suffix_len) {
  return (str_len >= suffix_len) &&
         (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}

void mmdoc_md_files(Array *md_files, char *base_path) {
  struct dirent *dp;
  DIR *dir = opendir(base_path);

  if (!dir)
    return;

  while ((dp = readdir(dir)) != NULL) {
    if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
      size_t size = strlen(base_path) + 1 + strlen(dp->d_name) + 1;
      char *path = malloc(size);
      strcpy(path, base_path);
      strcat(path, "/");
      strcat(path, dp->d_name);
      if (ends_with(dp->d_name, strlen(dp->d_name), ".md", strlen(".md")))
        insert_array(md_files, path);
      mmdoc_md_files(md_files, path);
      free(path);
    }
  }
  closedir(dir);
  return;
}

void mmdoc_img_files(Array *img_files, char *base_path) {
  struct dirent *dp;
  DIR *dir = opendir(base_path);

  if (!dir)
    return;

  while ((dp = readdir(dir)) != NULL) {
    if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
      size_t size = strlen(base_path) + 1 + strlen(dp->d_name) + 1;
      char *path = malloc(size);
      strcpy(path, base_path);
      strcat(path, "/");
      strcat(path, dp->d_name);
      if (ends_with(dp->d_name, strlen(dp->d_name), ".svg", strlen(".svg")) ||
          ends_with(dp->d_name, strlen(dp->d_name), ".jpeg", strlen(".jpeg")) ||
          ends_with(dp->d_name, strlen(dp->d_name), ".jpg", strlen(".jpg")) ||
          ends_with(dp->d_name, strlen(dp->d_name), ".webp", strlen(".webp")) ||
          ends_with(dp->d_name, strlen(dp->d_name), ".png", strlen(".png")) ||
          ends_with(dp->d_name, strlen(dp->d_name), ".gif", strlen(".gif")) ||
          ends_with(dp->d_name, strlen(dp->d_name), ".bmp", strlen(".bmp")))
        insert_array(img_files, path);
      mmdoc_img_files(img_files, path);
      free(path);
    }
  }
  closedir(dir);
  return;
}

enum ref_parse_state { NONE, L, REF };

void mmdoc_refs(Array *md_refs, char *path) {
  char ref[1024];
  int refpos = 0;
  FILE *file;
  file = fopen(path, "r");
  int c;
  enum ref_parse_state state = NONE;

  while (1) {
    c = fgetc(file);
    if (c == EOF)
      break;
    if (state == NONE && c == '(') {
      state = L;
      continue;
    }
    if (state == L && c == '#') {
      state = REF;
      ref[refpos] = c;
      refpos += 1;
      continue;
    }
    if (state == REF && (c == '\n' || c == '\r')) {
    } else if (state == REF && c != ')') {
      ref[refpos] = c;
      refpos += 1;
      continue;
    } else if (state == REF && c == ')') {
      ref[refpos] = '\0';
      insert_array(md_refs, ref);
    }
    refpos = 0;
    state = NONE;
    continue;
  }
  fclose(file);
}

void mmdoc_anchors(Array *md_anchors, char *path) {
  char ref[1024];
  int refpos = 0;
  FILE *file;
  file = fopen(path, "r");
  int c;
  enum ref_parse_state state = NONE;

  while (1) {
    c = fgetc(file);
    if (c == EOF)
      break;
    if (state == NONE && c == '{') {
      state = L;
      continue;
    }
    if (state == L && c == '#') {
      state = REF;
      ref[refpos] = c;
      refpos += 1;
      continue;
    }
    if (state == REF && (c == '\n' || c == '\r')) {
    } else if (state == REF && c != '}') {
      ref[refpos] = c;
      refpos += 1;
      continue;
    } else if (state == REF && c == '}') {
      ref[refpos] = '\0';
      insert_array(md_anchors, ref);
    }
    refpos = 0;
    state = NONE;
    continue;
  }
  fclose(file);
}

int copy_imgs(char *src, char *multi_dir, char *single_dir) {
  Array img_files;
  init_array(&img_files, 100);
  mmdoc_img_files(&img_files, src);

  for (int i = 0; i < img_files.used; i++) {
    int ch;
    char *source_path = img_files.array[i];
    FILE *source = fopen(source_path, "r");

    if (NULL == source) {
      printf("Failed to open file %s for reading: %s\n", source_path,
             strerror(errno));
      free_array(&img_files);
      return -1;
    }

    char *rel_path = source_path + strlen(src);
    char *multi_path = malloc(strlen(multi_dir) + 1 + strlen(rel_path) + 1);
    if (NULL == multi_path) {
      printf("Failed to allocate memory at %s line %d\n", __FILE__, __LINE__);
      fclose(source);
      free_array(&img_files);
      return -1;
    }
    sprintf(multi_path, "%s/%s", multi_dir, rel_path);
    char *single_path = malloc(strlen(single_dir) + 1 + strlen(rel_path) + 1);
    if (NULL == single_path) {
      printf("Failed to allocate memory at %s line %d\n", __FILE__, __LINE__);
      free(multi_path);
      fclose(source);
      free_array(&img_files);
      return -1;
    }

    sprintf(single_path, "%s/%s", single_dir, rel_path);

    FILE *multi = fopen(multi_path, "w");
    if (multi == NULL) {
      printf("Failed to open file %s for writing: %s\n", multi_path,
             strerror(errno));
      free(single_path);
      free(multi_path);
      fclose(source);
      free_array(&img_files);
      return -1;
    }
    free(multi_path);

    FILE *single = fopen(single_path, "w");
    if (single == NULL) {
      printf("Failed to open file %s for writing: %s\n", single_path,
             strerror(errno));
      fclose(multi);
      fclose(source);
      free_array(&img_files);
      return -1;
    }
    free(single_path);

    while ((ch = fgetc(source)) != EOF) {
      int ret;
      ret = fputc(ch, multi);
      if (ret != ch) {
        fclose(single);
        fclose(multi);
        fclose(source);
        free_array(&img_files);
        return -1;
      }
      ret = fputc(ch, single);
      if (ret != ch) {
        fclose(single);
        fclose(multi);
        fclose(source);
        free_array(&img_files);
        return -1;
      }
    }

    fclose(single);
    fclose(multi);
    fclose(source);
  }
  free_array(&img_files);
  return 0;
}

int main(int argc, char *argv[]) {
  char *project_name = NULL;
  char *src = NULL;
  char *out = NULL;
  if (argc != 4) {
    print_usage();
    return 1;
  }
  project_name = argv[1];
  src = argv[2];
  out = argv[3];

  char *src_relative_toc_path = "/toc.md";
  char *toc_path = malloc(strlen(src) + strlen(src_relative_toc_path) + 1);
  if (toc_path == NULL) {
    fprintf(stderr, "Fatal: failed to allocate memory for toc path.\n");
    return 1;
  }
  strcpy(toc_path, src);
  strcat(toc_path, src_relative_toc_path);
  if (access(toc_path, F_OK) != 0) {
    printf("Expected but did not find: \"%s\"", toc_path);
    return 1;
  }

  char *multi = "multi";
  char *out_multi = malloc(strlen(out) + 1 + strlen(multi) + 1);
  strcpy(out_multi, out);
  strcat(out_multi, "/");
  strcat(out_multi, multi);

  char *man = "/man/man1";
  char *out_man = malloc(strlen(out) + 1 + strlen(man) + 1);
  strcpy(out_man, out);
  strcat(out_man, man);
  if (mkdir_p(out_man) != 0) {
    printf("Error recursively making directory %s", out_man);
    return 1;
  }

  Array toc_refs;
  init_array(&toc_refs, 500);
  mmdoc_refs(&toc_refs, toc_path);

  if (toc_refs.used == 0) {
    printf("Error toc.md didn't reference any anchor.");
    return 1;
  }

  char *index_anchor = toc_refs.array[0];

  Array md_files;
  init_array(&md_files, 100);
  mmdoc_md_files(&md_files, src);

  AnchorLocationArray anchor_locations;
  init_anchor_location_array(&anchor_locations, 500);

  int count = 0;
  for (int i = 0; i < md_files.used; i++) {
    Array anchors;
    init_array(&anchors, 500);
    mmdoc_anchors(&anchors, md_files.array[i]);
    for (int j = 0; j < anchors.used; j++) {
      AnchorLocation *al = malloc(sizeof *al);
      al->anchor = anchors.array[j];
      al->file_path = md_files.array[i];

      char *page_path = malloc(strlen(out_multi) + strlen(al->file_path) + 12);
      strcpy(page_path, out_multi);
      strcat(page_path, al->file_path + strlen(src));
      char *lastExt = strrchr(page_path, '.');
      while (lastExt != NULL) {
        *lastExt = '\0';
        lastExt = strrchr(page_path, '.');
        if (lastExt < strrchr(page_path, '/'))
          break;
      }
      strcat(page_path, "/");
      char *page_dir_path = malloc(strlen(page_path) + 1);
      strcpy(page_dir_path, page_path);
      strcat(page_path, "index.html");
      al->multipage_output_file_path = page_path;
      al->multipage_output_directory_path = page_dir_path;
      al->multipage_url = page_dir_path + strlen(out_multi) + 1;

      uint directory_depth = 0;
      for (int k = 0; k < strlen(al->multipage_url); k++)
        if (al->multipage_url[k] == '/')
          directory_depth++;

      al->multipage_base_href = malloc(3 * directory_depth + 1);
      strcpy(al->multipage_base_href, "");
      for (int k = 0; k < directory_depth; k++)
        strcat(al->multipage_base_href, "../");

      al->title = mmdoc_render_get_title_from_file(al->file_path);

      if (strcmp(al->anchor, index_anchor) == 0) {
        char *index_html = "index.html";
        char *index_file_path =
            malloc(strlen(out_multi) + 1 + strlen(index_html) + 1);
        sprintf(index_file_path, "%s/%s", out_multi, index_html);
        al->multipage_output_file_path = index_file_path;
        al->multipage_output_directory_path = out_multi;
        al->multipage_url = "./";
        al->multipage_base_href = "";
      }

      if (mkdir_p(al->multipage_output_directory_path) != 0) {
        printf("Error recursively making directory %s",
               al->multipage_output_directory_path);
        return 1;
      }

      char *man_path = malloc(strlen(out_man) + 1 + strlen(project_name) +
                              strlen(al->file_path) + 2);

      int dash_count = 0;
      for (int k = 0; *(al->file_path + strlen(src) + k) != '\0'; k++) {
        char *c = al->file_path + strlen(src) + k;
        if (c[0] == '/')
          dash_count++;
        if (c[0] == '-')
          dash_count++;
      }
      char *man_page_name =
          malloc(strlen(project_name) + strlen(al->file_path) + dash_count + 1);
      man_page_name[0] = '\0';
      strcpy(man_path, out_man);
      strcat(man_path, "/");
      strcat(man_path, project_name);
      strcpy(man_page_name, project_name);
      for (int k = 0; *(al->file_path + strlen(src) + k) != '\0'; k++) {
        char *c = al->file_path + strlen(src) + k;
        if (c[0] == '/') {
          strcat(man_path, "-");
          strcat(man_page_name, "\\-");
        } else if (c[0] == '-') {
          strncat(man_path, c, 1);
          strcat(man_page_name, "\\-");
        } else {
          strncat(man_path, c, 1);
          strncat(man_page_name, c, 1);
        }
      }
      lastExt = strrchr(man_path, '.');
      while (lastExt != NULL) {
        *lastExt = '\0';
        lastExt = strrchr(man_path, '.');
      }
      lastExt = strrchr(man_page_name, '.');
      while (lastExt != NULL) {
        *lastExt = '\0';
        lastExt = strrchr(man_page_name, '.');
      }
      strcat(man_path, ".1");
      al->man_output_file_path = man_path;
      char *man_page_header =
          malloc(19 + strlen(man_path) * 2 + strlen(project_name) + 1);
      strcpy(man_page_header, ".TH \"");
      strcat(man_page_header, man_page_name);
      strcat(man_page_header, "\" \"1\" \"\" \"");
      strcat(man_page_header, project_name);
      strcat(man_page_header, "\" \"");
      strcat(man_page_header, man_page_name);
      strcat(man_page_header, "\"");
      al->man_header = man_page_header;
      insert_anchor_location_array(&anchor_locations, al);
      count++;
    }
  }

  AnchorLocationArray toc_anchor_locations;
  init_anchor_location_array(&toc_anchor_locations, toc_refs.used);

  for (int i = 0; i < toc_refs.used; i++) {
    AnchorLocation *anchor_location;
    int found = 0;
    for (int j = 0; j < anchor_locations.used; j++) {
      if (strcmp(toc_refs.array[i], anchor_locations.array[j].anchor) == 0) {
        anchor_location = &anchor_locations.array[j];
        found = 1;
        break;
      }
    }
    if (!found) {
      printf("Anchor \"%s\" referenced in toc.md not found.\n",
             toc_refs.array[i]);
      return 1;
    }
    insert_anchor_location_array(&toc_anchor_locations, anchor_location);
  }
  free_array(&toc_refs);

  char *single = "single";
  char *out_single = malloc(strlen(out) + 1 + strlen(single) + 1);
  strcpy(out_single, out);
  strcat(out_single, "/");
  strcat(out_single, single);
  if (mkdir_p(out_single) != 0) {
    printf("Error recursively making directory %s", out_single);
    return 1;
  }

  if (mmdoc_single(out_single, toc_path, project_name, toc_anchor_locations) !=
      0)
    return 1;

  if (mmdoc_multi(out_multi, src, toc_path, toc_anchor_locations,
                  anchor_locations, project_name) != 0)
    return 1;

  if (mkdir_p(out_man) != 0) {
    printf("Error recursively making directory %s", out_man);
    return -1;
  }
  if (mmdoc_man(out_man, src, toc_path, toc_anchor_locations,
                anchor_locations) != 0)
    return 1;

  char *epub = "epub";
  char *out_epub = malloc(strlen(out) + 1 + strlen(epub) + 1);
  sprintf(out_epub, "%s/%s", out, epub);
  if (mkdir_p(out_epub) != 0) {
    printf("Error recursively making directory %s", out_epub);
    return 1;
  }

  char *epub_ext = ".epub";
  char *out_epub_file =
      malloc(strlen(out) + 1 + strlen(project_name) + strlen(epub_ext) + 1);
  sprintf(out_epub_file, "%s/%s%s", out, project_name, epub_ext);

  if (mmdoc_epub(out_epub, out_epub_file, toc_path, toc_anchor_locations,
                 project_name) != 0)
    return 1;

  if (0 != copy_imgs(src, out_multi, out_single))
    return 1;

  free_array(&md_files);
  free_anchor_location_array(&toc_anchor_locations);
  free_anchor_location_array(&anchor_locations);
  return 0;
}
