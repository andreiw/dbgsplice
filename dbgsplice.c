/* Time-stamp: <2016-06-08 01:43:13 andreiw>
 * Copyright (C) 2012 Andrei Warkentin <andrey.warkentin@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _DEFAULT_SOURCE
#include <endian.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "pe32.h"

typedef struct f_state {
  int fd;
  struct stat st;
  void *d;
} f_state;

int validate_off(const f_state *f,
                 off_t off)
{
  if (off < f->st.st_size) {
    return 0;
  }

  return -1;
}

void *off_to_ptr(void *ptr,
                 off_t off)
{
  return (void *)(((uintptr_t) ptr) + off);
}

#define validate_ele(f, ptr, size)                                      \
  (validate_off(f, ((void *) ptr - (f)->d)) |                           \
   validate_off(f, ((void *) ptr - (f)->d) + (size - 1)))

int parse_f(const char *file,
            f_state *s)
{
  s->fd = open(file, 0);
  if (s->fd == -1) {
    fprintf(stderr, "Couldn't open '%s': %s\n", file, strerror(errno));
    return -1;
  }

  if (fstat(s->fd, &s->st) != 0) {
    fprintf(stderr, "Couldn't stat '%s': %s\n", file, strerror(errno));
    return -1;
  }

  s->d = mmap(NULL, s->st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                  s->fd, 0);
  if (s->d == NULL) {
    fprintf(stderr, "Couldn't mmap '%s': %s\n", file, strerror(errno));
    return -1;
  }

  return 0;
}

typedef struct dbg_state {
  f_state f;
  di_header *di;
  off_t symtab_offset;
  coff_symtab_hdr *symtab;
} dbg_state;

int parse_dbg(const char *file,
              dbg_state *s)
{
  int ret;
  off_t off;
  unsigned sec_count;
  unsigned dir_size;
  dbg_dir *dir, *dir_end;

  if ((ret = parse_f(file, &s->f)) < 0) {
    return ret;
  }

  s->di = s->f.d;
  if (validate_ele(&s->f, s->di, sizeof(*s->di)) < 0) {
    fprintf(stderr, "No IMAGE_SEPARATE_DEBUG_HEADER in '%s'\n", file);
    return -1;
  }

  if (le16toh(s->di->signature) != IMAGE_SEPARATE_DEBUG_SIGNATURE) {
    fprintf(stderr, "Bad IMAGE_SEPARATE_DEBUG_HEADER in '%s'\n", file);
    return -1;
  }

  sec_count = le32toh(s->di->number_of_sections);
  dir_size = le32toh(s->di->debug_directory_size);
  off = sizeof(di_header) + (sec_count * sizeof(pe32_sec)) +
    s->di->exported_names_size;

  dir = off_to_ptr(s->di, off);
  if (validate_ele(&s->f, dir, dir_size) < 0) {
    fprintf(stderr, "No IMAGE_DEBUG_DIRECTORY in '%s'\n", file);
    return -1;
  }

  s->symtab = NULL;
  for (dir_end = off_to_ptr(dir, dir_size);
       dir < dir_end;
       dir++) {
    if (le32toh(dir->type) == IMAGE_DEBUG_TYPE_COFF) {
      break;
    }
  }

  if (dir == dir_end) {
    fprintf(stderr, "No COFF symbol table in '%s'\n", file);
    return -1;
  }

  s->symtab_offset = le32toh(dir->pointer_to_data);
  s->symtab = off_to_ptr(s->di, s->symtab_offset);
  if (validate_ele(&s->f, s->symtab, sizeof(s->symtab)) < 0) {
    fprintf(stderr, "Bad COFF symbol table in '%s'\n", file);
    return -1;
  }

  return 0;
}

typedef struct exe_state {
  f_state f;
  pe32_hdr *pe;
} exe_state;

int parse_exe(const char *file,
              exe_state *s)
{
  int ret;
  mz_hdr *mz;

  if ((ret = parse_f(file, &s->f)) < 0) {
    return ret;
  }

  mz = s->f.d;
  if (validate_ele(&s->f, mz, sizeof(*mz)) == 0 &&
      le16toh(mz->e_magic) == PE32_DOS_MAGIC) {

    s->pe = off_to_ptr(mz, le32toh(mz->e_lfanew) + 4);
  } else {
    s->pe = s->f.d;
  }

  if (validate_ele(&s->f, s->pe, sizeof(*s->pe)) != 0) {
    fprintf(stderr, "No PE header in '%s'\n", file);
    return -1;
  }

  if (le16toh(mz->e_magic) == PE32_DOS_MAGIC) {
    uint32_t *magic = (uint32_t *) s->pe - 1;
    if (le32toh(*magic) != PE32_MAGIC) {
      fprintf(stderr, "Bad PE header in '%s'\n", file);
      return -1;
    }
  }

  return 0;
}

int link_dbg_exe(const dbg_state *ds,
                 const exe_state *es)
{
  static char *m = "DBG and EXE probably unrelated, don't match on: %s\n";

  if (le16toh(es->pe->machine) !=
      le16toh(ds->di->machine)) {
    fprintf(stderr, m, "machine type");
    return -1;
  }

  if (le32toh(es->pe->time_date_stamp) !=
      le32toh(ds->di->time_date_stamp)) {
    fprintf(stderr, m, "time stamp");
    return -1;
  }

  if (le16toh(es->pe->sections) !=
      le32toh(ds->di->number_of_sections)) {
    fprintf(stderr, m, "section count");
    return -1;
  }

  if (le32toh(es->pe->number_of_syms) !=
      le32toh(ds->symtab->number_of_syms)) {
    fprintf(stderr, m, "symbol count");
    return -1;
  }

  es->pe->pointer_to_symtab = htole32(
    es->f.st.st_size + ds->symtab_offset +
    sizeof(coff_symtab_hdr));

  es->pe->chars = htole16(
    le16toh(es->pe->chars) & ~(IMAGE_FILE_DEBUG_STRIPPED |
                               IMAGE_FILE_LOCAL_SYMS_STRIPPED |
                               IMAGE_FILE_LINE_NUMS_STRIPPED));;
  return 0;
}

int write_new(const char *file,
              const dbg_state *ds,
              const exe_state *es)
{
  int fd;
  uint8_t *d;
  off_t size;

  fd = open(file, O_RDWR | O_CREAT | O_EXCL, 0666);
  if (fd == -1) {
    fprintf(stderr, "Couldn't create '%s': %s\n", file, strerror(errno));
    return -1;
  }

  size = ds->f.st.st_size + es->f.st.st_size;
  if (lseek(fd, size - 1, SEEK_SET) != size - 1) {
    fprintf(stderr, "Couldn't seek '%s': %s\n", file, strerror(errno));
    return -1;
  }
  if (write(fd, " ", 1) != 1) {
    fprintf(stderr, "Couldn't write '%s': %s\n", file, strerror(errno));
    return -1;
  }

  d = mmap(NULL, size,
           PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (d == NULL) {
    fprintf(stderr, "Couldn't mmap '%s': %s\n", file, strerror(errno));
    return -1;
  }

  memcpy(d, es->f.d, es->f.st.st_size);
  memcpy(d + es->f.st.st_size, ds->f.d, ds->f.st.st_size);
  munmap(d, size);
  close(fd);

  return 0;
}

int main(int argc,
         const char **argv)
{
  const char *dbg_file;
  const char *exe_file;
  const char *new_file;
  dbg_state ds;
  exe_state es;

  if (argc < 4) {
    fprintf(stderr, "Usage: %s file.dbg file.exe new.exe\n", argv[0]);
    return 1;
  }

  dbg_file = argv[1];
  exe_file = argv[2];
  new_file = argv[3];
  if (parse_dbg(dbg_file, &ds) < 0) {
    return 2;
  }

  if (parse_exe(exe_file, &es) < 0) {
    return 3;
  }

  if (link_dbg_exe(&ds, &es) < 0) {
    return 4;
  }

  if (write_new(new_file, &ds, &es) < 0) {
    return 5;
  }

  printf("Done!\n");
  return 0;
}
