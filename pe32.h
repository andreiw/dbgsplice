/* Time-stamp: <2016-06-08 01:18:28 andreiw>
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

#ifndef PE32_H
#define PE32_H

#define PE32_DOS_MAGIC 0x5A4D
#define PE32_HDR_OFFSET 0x3c
#define PE32_MAGIC 0x00004550

typedef struct mz_hdr {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;
} mz_hdr;

typedef struct di_header {
#define IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4944
  uint16_t signature;
  uint16_t flags;
  uint16_t machine;
  uint16_t chars;
  uint32_t time_date_stamp;
  uint32_t checksum;
  uint32_t image_base;
  uint32_t size_of_image;
  uint32_t number_of_sections;
  uint32_t exported_names_size;
  uint32_t debug_directory_size;
  uint32_t section_alignment;
  uint32_t reserved[2];
} di_header;

typedef struct dbg_dir {
  uint32_t characteristics;
  uint32_t time_date_stamp;
  uint16_t major_version;
  uint16_t minor_version;
#define IMAGE_DEBUG_TYPE_COFF 1
  uint32_t type;
  uint32_t size_of_data;
  uint32_t address_of_data;
  uint32_t pointer_to_data;
} dbg_dir;

typedef struct pe32_hdr {
  uint16_t machine;
  uint16_t sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symtab;
  uint32_t number_of_syms;
  uint16_t sizeof_opt;
#define IMAGE_FILE_DEBUG_STRIPPED      0x0200
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_LINE_NUMS_STRIPPED  0x0004
  uint16_t chars;
} pe32_hdr;

typedef struct pe32_sec {
  uint8_t name[8];
  uint32_t mem_size;
  uint32_t va;
  uint32_t file_size;
  uint32_t off_data;
  uint32_t off_rel;
  uint32_t off_lines;
  uint16_t relocs;
  uint16_t lines;
  uint32_t chars;
} pe32_sec;

typedef struct coff_symtab_hdr {
  uint32_t number_of_syms;
  uint32_t lva_to_first_symbol;
  uint32_t number_of_line_numbers;
  uint32_t lva_to_first_line_number;
  uint32_t rva_to_first_byte_of_code;
  uint32_t rva_to_last_byte_of_code;
  uint32_t rva_to_girst_byte_of_data;
  uint32_t rva_to_last_byte_of_data;
} coff_symtab_hdr;

#endif /* PE32_H */
