/* IBM S/390-specific support for 32-bit ELF
   Copyright (C) 2000-2025 Free Software Foundation, Inc.
   Contributed by Carl B. Pedersen and Martin Schwidefsky.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/s390.h"
#include <stdarg.h>

static bfd_reloc_status_type
s390_tls_reloc (bfd *, arelent *, asymbol *, void *,
		asection *, bfd *, char **);
static bfd_reloc_status_type
s390_elf_ldisp_reloc (bfd *, arelent *, asymbol *, void *,
		      asection *, bfd *, char **);

/* The relocation "howto" table.  */

static reloc_howto_type elf_howto_table[] =
{
  HOWTO (R_390_NONE,		/* type */
	 0,			/* rightshift */
	 0,			/* size */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc, /* special_function */
	 "R_390_NONE",		/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */

  HOWTO(R_390_8,	 0, 1,	8, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_8",	 false, 0,0x000000ff, false),
  HOWTO(R_390_12,	 0, 2, 12, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_390_12",	 false, 0,0x00000fff, false),
  HOWTO(R_390_16,	 0, 2, 16, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_16",	 false, 0,0x0000ffff, false),
  HOWTO(R_390_32,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_32",	 false, 0,0xffffffff, false),
  HOWTO(R_390_PC32,	 0, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PC32",	 false, 0,0xffffffff, true),
  HOWTO(R_390_GOT12,	 0, 2, 12, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOT12",	 false, 0,0x00000fff, false),
  HOWTO(R_390_GOT32,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOT32",	 false, 0,0xffffffff, false),
  HOWTO(R_390_PLT32,	 0, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PLT32",	 false, 0,0xffffffff, true),
  HOWTO(R_390_COPY,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_COPY",	 false, 0,0xffffffff, false),
  HOWTO(R_390_GLOB_DAT,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GLOB_DAT", false, 0,0xffffffff, false),
  HOWTO(R_390_JMP_SLOT,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_JMP_SLOT", false, 0,0xffffffff, false),
  HOWTO(R_390_RELATIVE,	 0, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_RELATIVE", false, 0,0xffffffff, false),
  HOWTO(R_390_GOTOFF32,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTOFF32", false, 0,0xffffffff, false),
  HOWTO(R_390_GOTPC,	 0, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTPC",	 false, 0,0xffffffff, true),
  HOWTO(R_390_GOT16,	 0, 2, 16, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOT16",	 false, 0,0x0000ffff, false),
  HOWTO(R_390_PC16,	 0, 2, 16,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PC16",	 false, 0,0x0000ffff, true),
  HOWTO(R_390_PC16DBL,	 1, 2, 16,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PC16DBL",	 false, 0,0x0000ffff, true),
  HOWTO(R_390_PLT16DBL,	 1, 2, 16,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PLT16DBL", false, 0,0x0000ffff, true),
  HOWTO(R_390_PC32DBL,	 1, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PC32DBL",	 false, 0,0xffffffff, true),
  HOWTO(R_390_PLT32DBL,	 1, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PLT32DBL", false, 0,0xffffffff, true),
  HOWTO(R_390_GOTPCDBL,	 1, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTPCDBL", false, 0,0xffffffff, true),
  EMPTY_HOWTO (R_390_64),	/* Empty entry for R_390_64.  */
  EMPTY_HOWTO (R_390_PC64),	/* Empty entry for R_390_PC64.  */
  EMPTY_HOWTO (R_390_GOT64),	/* Empty entry for R_390_GOT64.  */
  EMPTY_HOWTO (R_390_PLT64),	/* Empty entry for R_390_PLT64.  */
  HOWTO(R_390_GOTENT,	 1, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTENT",	 false, 0,0xffffffff, true),
  HOWTO(R_390_GOTOFF16,	 0, 2, 16, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTOFF16", false, 0,0x0000ffff, false),
  EMPTY_HOWTO (R_390_GOTOFF64),	/* Empty entry for R_390_GOTOFF64.  */
  HOWTO(R_390_GOTPLT12,	 0, 2, 12, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_390_GOTPLT12", false, 0,0x00000fff, false),
  HOWTO(R_390_GOTPLT16,	 0, 2, 16, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTPLT16", false, 0,0x0000ffff, false),
  HOWTO(R_390_GOTPLT32,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTPLT32", false, 0,0xffffffff, false),
  EMPTY_HOWTO (R_390_GOTPLT64),	/* Empty entry for R_390_GOTPLT64.  */
  HOWTO(R_390_GOTPLTENT, 1, 4, 32,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_GOTPLTENT",false, 0,0xffffffff, true),
  HOWTO(R_390_PLTOFF16,	 0, 2, 16, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PLTOFF16", false, 0,0x0000ffff, false),
  HOWTO(R_390_PLTOFF32,	 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PLTOFF32", false, 0,0xffffffff, false),
  EMPTY_HOWTO (R_390_PLTOFF64),	/* Empty entry for R_390_PLTOFF64.  */
  HOWTO(R_390_TLS_LOAD, 0, 0, 0, false, 0, complain_overflow_dont,
	s390_tls_reloc, "R_390_TLS_LOAD", false, 0, 0, false),
  HOWTO(R_390_TLS_GDCALL, 0, 0, 0, false, 0, complain_overflow_dont,
	s390_tls_reloc, "R_390_TLS_GDCALL", false, 0, 0, false),
  HOWTO(R_390_TLS_LDCALL, 0, 0, 0, false, 0, complain_overflow_dont,
	s390_tls_reloc, "R_390_TLS_LDCALL", false, 0, 0, false),
  HOWTO(R_390_TLS_GD32, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_GD32", false, 0, 0xffffffff, false),
  EMPTY_HOWTO (R_390_TLS_GD64),	/* Empty entry for R_390_TLS_GD64.  */
  HOWTO(R_390_TLS_GOTIE12, 0, 2, 12, false, 0, complain_overflow_dont,
	bfd_elf_generic_reloc, "R_390_TLS_GOTIE12", false, 0, 0x00000fff, false),
  HOWTO(R_390_TLS_GOTIE32, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_GOTIE32", false, 0, 0xffffffff, false),
  EMPTY_HOWTO (R_390_TLS_GOTIE64),	/* Empty entry for R_390_TLS_GOTIE64.  */
  HOWTO(R_390_TLS_LDM32, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_LDM32", false, 0, 0xffffffff, false),
  EMPTY_HOWTO (R_390_TLS_LDM64),	/* Empty entry for R_390_TLS_LDM64.  */
  HOWTO(R_390_TLS_IE32, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_IE32", false, 0, 0xffffffff, false),
  EMPTY_HOWTO (R_390_TLS_IE64),	/* Empty entry for R_390_TLS_IE64.  */
  HOWTO(R_390_TLS_IEENT, 1, 4, 32, true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_IEENT", false, 0, 0xffffffff, true),
  HOWTO(R_390_TLS_LE32, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_LE32", false, 0, 0xffffffff, false),
  EMPTY_HOWTO (R_390_TLS_LE64),	/* Empty entry for R_390_TLS_LE64.  */
  HOWTO(R_390_TLS_LDO32, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_LDO32", false, 0, 0xffffffff, false),
  EMPTY_HOWTO (R_390_TLS_LDO64),	/* Empty entry for R_390_TLS_LDO64.  */
  HOWTO(R_390_TLS_DTPMOD, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_DTPMOD", false, 0, 0xffffffff, false),
  HOWTO(R_390_TLS_DTPOFF, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_DTPOFF", false, 0, 0xffffffff, false),
  HOWTO(R_390_TLS_TPOFF, 0, 4, 32, false, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_TLS_TPOFF", false, 0, 0xffffffff, false),
  HOWTO(R_390_20,	 0, 4, 20, false, 8, complain_overflow_dont,
	s390_elf_ldisp_reloc, "R_390_20",      false, 0,0x0fffff00, false),
  HOWTO(R_390_GOT20,	 0, 4, 20, false, 8, complain_overflow_dont,
	s390_elf_ldisp_reloc, "R_390_GOT20",   false, 0,0x0fffff00, false),
  HOWTO(R_390_GOTPLT20,	 0, 4, 20, false, 8, complain_overflow_dont,
	s390_elf_ldisp_reloc, "R_390_GOTPLT20", false, 0,0x0fffff00, false),
  HOWTO(R_390_TLS_GOTIE20, 0, 4, 20, false, 8, complain_overflow_dont,
	s390_elf_ldisp_reloc, "R_390_TLS_GOTIE20", false, 0,0x0fffff00, false),
  HOWTO(R_390_IRELATIVE, 0, 4, 32, true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_IRELATIVE", false, 0, 0xffffffff, false),
  HOWTO(R_390_PC12DBL,	 1, 2, 12,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PC12DBL",	 false, 0,0x00000fff, true),
  HOWTO(R_390_PLT12DBL,	 1, 2, 12,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PLT12DBL", false, 0,0x00000fff, true),
  HOWTO(R_390_PC24DBL,	 1, 4, 24,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PC24DBL",	 false, 0,0x00ffffff, true),
  HOWTO(R_390_PLT24DBL,	 1, 4, 24,  true, 0, complain_overflow_bitfield,
	bfd_elf_generic_reloc, "R_390_PLT24DBL", false, 0,0x00ffffff, true),
};

/* GNU extension to record C++ vtable hierarchy.  */
static reloc_howto_type elf32_s390_vtinherit_howto =
  HOWTO (R_390_GNU_VTINHERIT, 0,4,0,false,0,complain_overflow_dont, NULL, "R_390_GNU_VTINHERIT", false,0, 0, false);
static reloc_howto_type elf32_s390_vtentry_howto =
  HOWTO (R_390_GNU_VTENTRY, 0,4,0,false,0,complain_overflow_dont, _bfd_elf_rel_vtable_reloc_fn,"R_390_GNU_VTENTRY", false,0,0, false);

static reloc_howto_type *
elf_s390_reloc_type_lookup(bfd *abfd ATTRIBUTE_UNUSED,
                          bfd_reloc_code_real_type code)
{
    typedef struct {
        bfd_reloc_code_real_type code;
        int howto_index;
        reloc_howto_type *special_howto;
    } reloc_mapping_t;

    static const reloc_mapping_t reloc_map[] = {
        {BFD_RELOC_NONE, R_390_NONE, NULL},
        {BFD_RELOC_8, R_390_8, NULL},
        {BFD_RELOC_390_12, R_390_12, NULL},
        {BFD_RELOC_16, R_390_16, NULL},
        {BFD_RELOC_32, R_390_32, NULL},
        {BFD_RELOC_CTOR, R_390_32, NULL},
        {BFD_RELOC_32_PCREL, R_390_PC32, NULL},
        {BFD_RELOC_390_GOT12, R_390_GOT12, NULL},
        {BFD_RELOC_32_GOT_PCREL, R_390_GOT32, NULL},
        {BFD_RELOC_390_PLT32, R_390_PLT32, NULL},
        {BFD_RELOC_390_COPY, R_390_COPY, NULL},
        {BFD_RELOC_390_GLOB_DAT, R_390_GLOB_DAT, NULL},
        {BFD_RELOC_390_JMP_SLOT, R_390_JMP_SLOT, NULL},
        {BFD_RELOC_390_RELATIVE, R_390_RELATIVE, NULL},
        {BFD_RELOC_32_GOTOFF, R_390_GOTOFF32, NULL},
        {BFD_RELOC_390_GOTPC, R_390_GOTPC, NULL},
        {BFD_RELOC_390_GOT16, R_390_GOT16, NULL},
        {BFD_RELOC_16_PCREL, R_390_PC16, NULL},
        {BFD_RELOC_390_PC12DBL, R_390_PC12DBL, NULL},
        {BFD_RELOC_390_PLT12DBL, R_390_PLT12DBL, NULL},
        {BFD_RELOC_390_PC16DBL, R_390_PC16DBL, NULL},
        {BFD_RELOC_390_PLT16DBL, R_390_PLT16DBL, NULL},
        {BFD_RELOC_390_PC24DBL, R_390_PC24DBL, NULL},
        {BFD_RELOC_390_PLT24DBL, R_390_PLT24DBL, NULL},
        {BFD_RELOC_390_PC32DBL, R_390_PC32DBL, NULL},
        {BFD_RELOC_390_PLT32DBL, R_390_PLT32DBL, NULL},
        {BFD_RELOC_390_GOTPCDBL, R_390_GOTPCDBL, NULL},
        {BFD_RELOC_390_GOTENT, R_390_GOTENT, NULL},
        {BFD_RELOC_16_GOTOFF, R_390_GOTOFF16, NULL},
        {BFD_RELOC_390_GOTPLT12, R_390_GOTPLT12, NULL},
        {BFD_RELOC_390_GOTPLT16, R_390_GOTPLT16, NULL},
        {BFD_RELOC_390_GOTPLT32, R_390_GOTPLT32, NULL},
        {BFD_RELOC_390_GOTPLTENT, R_390_GOTPLTENT, NULL},
        {BFD_RELOC_390_PLTOFF16, R_390_PLTOFF16, NULL},
        {BFD_RELOC_390_PLTOFF32, R_390_PLTOFF32, NULL},
        {BFD_RELOC_390_TLS_LOAD, R_390_TLS_LOAD, NULL},
        {BFD_RELOC_390_TLS_GDCALL, R_390_TLS_GDCALL, NULL},
        {BFD_RELOC_390_TLS_LDCALL, R_390_TLS_LDCALL, NULL},
        {BFD_RELOC_390_TLS_GD32, R_390_TLS_GD32, NULL},
        {BFD_RELOC_390_TLS_GOTIE12, R_390_TLS_GOTIE12, NULL},
        {BFD_RELOC_390_TLS_GOTIE32, R_390_TLS_GOTIE32, NULL},
        {BFD_RELOC_390_TLS_LDM32, R_390_TLS_LDM32, NULL},
        {BFD_RELOC_390_TLS_IE32, R_390_TLS_IE32, NULL},
        {BFD_RELOC_390_TLS_IEENT, R_390_TLS_IEENT, NULL},
        {BFD_RELOC_390_TLS_LE32, R_390_TLS_LE32, NULL},
        {BFD_RELOC_390_TLS_LDO32, R_390_TLS_LDO32, NULL},
        {BFD_RELOC_390_TLS_DTPMOD, R_390_TLS_DTPMOD, NULL},
        {BFD_RELOC_390_TLS_DTPOFF, R_390_TLS_DTPOFF, NULL},
        {BFD_RELOC_390_TLS_TPOFF, R_390_TLS_TPOFF, NULL},
        {BFD_RELOC_390_20, R_390_20, NULL},
        {BFD_RELOC_390_GOT20, R_390_GOT20, NULL},
        {BFD_RELOC_390_GOTPLT20, R_390_GOTPLT20, NULL},
        {BFD_RELOC_390_TLS_GOTIE20, R_390_TLS_GOTIE20, NULL},
        {BFD_RELOC_390_IRELATIVE, R_390_IRELATIVE, NULL},
        {BFD_RELOC_VTABLE_INHERIT, 0, &elf32_s390_vtinherit_howto},
        {BFD_RELOC_VTABLE_ENTRY, 0, &elf32_s390_vtentry_howto}
    };

    const size_t map_size = sizeof(reloc_map) / sizeof(reloc_map[0]);
    
    for (size_t i = 0; i < map_size; i++) {
        if (reloc_map[i].code == code) {
            if (reloc_map[i].special_howto != NULL) {
                return reloc_map[i].special_howto;
            }
            return &elf_howto_table[reloc_map[i].howto_index];
        }
    }
    
    return NULL;
}

static reloc_howto_type *
elf_s390_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    const char *r_name)
{
  unsigned int i;
  const unsigned int howto_table_size = sizeof (elf_howto_table) / sizeof (elf_howto_table[0]);

  if (r_name == NULL)
    return NULL;

  for (i = 0; i < howto_table_size; i++)
    {
      if (elf_howto_table[i].name != NULL
	  && strcasecmp (elf_howto_table[i].name, r_name) == 0)
	return &elf_howto_table[i];
    }

  if (elf32_s390_vtinherit_howto.name != NULL
      && strcasecmp (elf32_s390_vtinherit_howto.name, r_name) == 0)
    return &elf32_s390_vtinherit_howto;

  if (elf32_s390_vtentry_howto.name != NULL
      && strcasecmp (elf32_s390_vtentry_howto.name, r_name) == 0)
    return &elf32_s390_vtentry_howto;

  return NULL;
}

/* We need to use ELF32_R_TYPE so we have our own copy of this function,
   and elf32-s390.c has its own copy.  */

static bool
elf_s390_info_to_howto (bfd *abfd,
			arelent *cache_ptr,
			Elf_Internal_Rela *dst)
{
  unsigned int r_type;
  size_t howto_table_size;

  if (!abfd || !cache_ptr || !dst)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  r_type = ELF32_R_TYPE(dst->r_info);

  switch (r_type)
    {
    case R_390_GNU_VTINHERIT:
      cache_ptr->howto = &elf32_s390_vtinherit_howto;
      return true;

    case R_390_GNU_VTENTRY:
      cache_ptr->howto = &elf32_s390_vtentry_howto;
      return true;

    default:
      howto_table_size = sizeof (elf_howto_table) / sizeof (elf_howto_table[0]);
      if (r_type >= howto_table_size)
	{
	  _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			      abfd, r_type);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      cache_ptr->howto = &elf_howto_table[r_type];
      return true;
    }
}

/* A relocation function which doesn't do anything.  */
static bfd_reloc_status_type
s390_tls_reloc (bfd *abfd ATTRIBUTE_UNUSED,
		arelent *reloc_entry,
		asymbol *symbol ATTRIBUTE_UNUSED,
		void * data ATTRIBUTE_UNUSED,
		asection *input_section,
		bfd *output_bfd,
		char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd && reloc_entry && input_section)
    reloc_entry->address += input_section->output_offset;
  return bfd_reloc_ok;
}

/* Handle the large displacement relocs.  */
static bfd_reloc_status_type
s390_elf_ldisp_reloc (bfd *abfd ATTRIBUTE_UNUSED,
		      arelent *reloc_entry,
		      asymbol *symbol,
		      void * data ATTRIBUTE_UNUSED,
		      asection *input_section,
		      bfd *output_bfd,
		      char **error_message ATTRIBUTE_UNUSED)
{
  reloc_howto_type *howto = reloc_entry->howto;
  bfd_vma relocation;
  bfd_vma insn;
  bfd_signed_vma signed_relocation;

  if (output_bfd != NULL
      && (symbol->flags & BSF_SECTION_SYM) == 0
      && (!howto->partial_inplace || reloc_entry->addend == 0))
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  if (output_bfd != NULL)
    return bfd_reloc_continue;

  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;

  relocation = symbol->value
	       + symbol->section->output_section->vma
	       + symbol->section->output_offset
	       + reloc_entry->addend;

  if (howto->pc_relative)
    {
      relocation -= input_section->output_section->vma
		    + input_section->output_offset
		    + reloc_entry->address;
    }

  insn = bfd_get_32 (abfd, (bfd_byte *) data + reloc_entry->address);
  insn |= (relocation & 0xfff) << 16 | (relocation & 0xff000) >> 4;
  bfd_put_32 (abfd, insn, (bfd_byte *) data + reloc_entry->address);

  signed_relocation = (bfd_signed_vma) relocation;
  if (signed_relocation < -0x80000 || signed_relocation > 0x7ffff)
    return bfd_reloc_overflow;

  return bfd_reloc_ok;
}

static bool
elf_s390_is_local_label_name (bfd *abfd, const char *name)
{
  if (!name)
    return false;

  if (name[0] == '.' && (name[1] == 'X' || name[1] == 'L'))
    return true;

  return _bfd_elf_is_local_label_name (abfd, name);
}

/* Functions for the 390 ELF linker.  */

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF_DYNAMIC_INTERPRETER "/lib/ld.so.1"

/* If ELIMINATE_COPY_RELOCS is non-zero, the linker will try to avoid
   copying dynamic variables from a shared lib into an app's dynbss
   section, and instead use a dynamic relocation to point into the
   shared lib.  */
#define ELIMINATE_COPY_RELOCS 1

/* The size in bytes of the first entry in the procedure linkage table.  */
#define PLT_FIRST_ENTRY_SIZE 32
/* The size in bytes of an entry in the procedure linkage table.  */
#define PLT_ENTRY_SIZE 32

#define GOT_ENTRY_SIZE 4

#define RELA_ENTRY_SIZE sizeof (Elf32_External_Rela)

/* The first three entries in a procedure linkage table are reserved,
   and the initial contents are unimportant (we zero them out).
   Subsequent entries look like this.  See the SVR4 ABI 386
   supplement to see how this works.  */

/* For the s390, simple addr offset can only be 0 - 4096.
   To use the full 2 GB address space, several instructions
   are needed to load an address in a register and execute
   a branch( or just saving the address)

   Furthermore, only r 0 and 1 are free to use!!!  */

/* The first 3 words in the GOT are then reserved.
   Word 0 is the address of the dynamic table.
   Word 1 is a pointer to a structure describing the object
   Word 2 is used to point to the loader entry address.

   The code for position independent PLT entries looks like this:

   r12 holds addr of the current GOT at entry to the PLT

   The GOT holds the address in the PLT to be executed.
   The loader then gets:
   24(15) =  Pointer to the structure describing the object.
   28(15) =  Offset into rela.plt

   The loader  must  then find the module where the function is
   and insert the address in the GOT.

  Note: 390 can only address +- 64 K relative.
	We check if offset > 65536, then make a relative branch -64xxx
	back to a previous defined branch

PLT1: BASR 1,0	       # 2 bytes
      L	   1,22(1)     # 4 bytes  Load offset in GOT in r 1
      L	   1,(1,12)    # 4 bytes  Load address from GOT in r1
      BCR  15,1	       # 2 bytes  Jump to address
RET1: BASR 1,0	       # 2 bytes  Return from GOT 1st time
      L	   1,14(1)     # 4 bytes  Load offset in symol table in r1
      BRC  15,-x       # 4 bytes  Jump to start of PLT
      .word 0	       # 2 bytes filler
      .long ?	       # 4 bytes  offset in GOT
      .long ?	       # 4 bytes  offset into rela.plt

  This was the general case. There are two additional, optimizes PLT
  definitions. One for GOT offsets < 4096 and one for GOT offsets < 32768.
  First the one for GOT offsets < 4096:

PLT1: L	   1,<offset>(12) # 4 bytes  Load address from GOT in R1
      BCR  15,1		  # 2 bytes  Jump to address
      .word 0,0,0	  # 6 bytes  filler
RET1: BASR 1,0		  # 2 bytes  Return from GOT 1st time
      L	   1,14(1)	  # 4 bytes  Load offset in rela.plt in r1
      BRC  15,-x	  # 4 bytes  Jump to start of PLT
      .word 0,0,0	  # 6 bytes  filler
      .long ?		  # 4 bytes  offset into rela.plt

  Second the one for GOT offsets < 32768:

PLT1: LHI  1,<offset>	  # 4 bytes  Load offset in GOT to r1
      L	   1,(1,12)	  # 4 bytes  Load address from GOT to r1
      BCR  15,1		  # 2 bytes  Jump to address
      .word 0		  # 2 bytes  filler
RET1: BASR 1,0		  # 2 bytes  Return from GOT 1st time
      L	   1,14(1)	  # 4 bytes  Load offset in rela.plt in r1
      BRC  15,-x	  # 4 bytes  Jump to start of PLT
      .word 0,0,0	  # 6 bytes  filler
      .long ?		  # 4 bytes  offset into rela.plt

Total = 32 bytes per PLT entry

   The code for static build PLT entries looks like this:

PLT1: BASR 1,0	       # 2 bytes
      L	   1,22(1)     # 4 bytes  Load address of GOT entry
      L	   1,0(0,1)    # 4 bytes  Load address from GOT in r1
      BCR  15,1	       # 2 bytes  Jump to address
RET1: BASR 1,0	       # 2 bytes  Return from GOT 1st time
      L	   1,14(1)     # 4 bytes  Load offset in symbol table in r1
      BRC  15,-x       # 4 bytes  Jump to start of PLT
      .word 0	       # 2 bytes  filler
      .long ?	       # 4 bytes  address of GOT entry
      .long ?	       # 4 bytes  offset into rela.plt  */

static const bfd_byte elf_s390_plt_entry[PLT_ENTRY_SIZE] =
  {
    0x0d, 0x10,				    /* basr    %r1,%r0	   */
    0x58, 0x10, 0x10, 0x16,		    /* l       %r1,22(%r1) */
    0x58, 0x10, 0x10, 0x00,		    /* l       %r1,0(%r1)  */
    0x07, 0xf1,				    /* br      %r1	   */
    0x0d, 0x10,				    /* basr    %r1,%r0	   */
    0x58, 0x10, 0x10, 0x0e,		    /* l       %r1,14(%r1) */
    0xa7, 0xf4, 0x00, 0x00,		    /* j       first plt   */
    0x00, 0x00,				    /* padding		   */
    0x00, 0x00, 0x00, 0x00,		    /* GOT offset	   */
    0x00, 0x00, 0x00, 0x00		    /* rela.plt offset	   */
  };

/* Generic PLT pic entry.  */
static const bfd_byte elf_s390_plt_pic_entry[PLT_ENTRY_SIZE] =
  {
    0x0d, 0x10,				    /* basr    %r1,%r0	       */
    0x58, 0x10, 0x10, 0x16,		    /* l       %r1,22(%r1)     */
    0x58, 0x11, 0xc0, 0x00,		    /* l       %r1,0(%r1,%r12) */
    0x07, 0xf1,				    /* br      %r1	       */
    0x0d, 0x10,				    /* basr    %r1,%r0	       */
    0x58, 0x10, 0x10, 0x0e,		    /* l       %r1,14(%r1)     */
    0xa7, 0xf4, 0x00, 0x00,		    /* j       first plt       */
    0x00, 0x00,				    /* padding		       */
    0x00, 0x00, 0x00, 0x00,		    /* GOT offset	       */
    0x00, 0x00, 0x00, 0x00		    /* rela.plt offset	       */
  };

/* Optimized PLT pic entry for GOT offset < 4k.  xx will be replaced
   when generating the PLT slot with the GOT offset.  */
static const bfd_byte elf_s390_plt_pic12_entry[PLT_ENTRY_SIZE] =
  {
    0x58, 0x10, 0xc0, 0x00,		    /* l       %r1,xx(%r12) */
    0x07, 0xf1,				    /* br      %r1	    */
    0x00, 0x00, 0x00, 0x00,		    /* padding		    */
    0x00, 0x00,
    0x0d, 0x10,				    /* basr    %r1,%r0	    */
    0x58, 0x10, 0x10, 0x0e,		    /* l       %r1,14(%r1)  */
    0xa7, 0xf4, 0x00, 0x00,		    /* j       first plt    */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

/* Optimized PLT pic entry for GOT offset < 32k.  xx will be replaced
   when generating the PLT slot with the GOT offset.  */
static const bfd_byte elf_s390_plt_pic16_entry[PLT_ENTRY_SIZE] =
  {
    0xa7, 0x18, 0x00, 0x00,		    /* lhi     %r1,xx	       */
    0x58, 0x11, 0xc0, 0x00,		    /* l       %r1,0(%r1,%r12) */
    0x07, 0xf1,				    /* br      %r1	       */
    0x00, 0x00,
    0x0d, 0x10,				    /* basr    %r1,%r0	       */
    0x58, 0x10, 0x10, 0x0e,		    /* l       %r1,14(%r1)     */
    0xa7, 0xf4, 0x00, 0x00,		    /* j       first plt       */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
  };

/* The first PLT entry pushes the offset into the rela.plt
   from R1 onto the stack at 8(15) and the loader object info
   at 12(15), loads the loader address in R1 and jumps to it.  */

/* The first entry in the PLT for PIC code:

PLT0:
   ST	1,28(15)  # R1 has offset into rela.plt
   L	1,4(12)	  # Get loader ino(object struct address)
   ST	1,24(15)  # Store address
   L	1,8(12)	  # Entry address of loader in R1
   BR	1	  # Jump to loader

   The first entry in the PLT for static code:

PLT0:
   ST	1,28(15)      # R1 has offset into rela.plt
   BASR 1,0
   L	1,18(0,1)     # Get address of GOT
   MVC	24(4,15),4(1) # Move loader ino to stack
   L	1,8(1)	      # Get address of loader
   BR	1	      # Jump to loader
   .word 0	      # filler
   .long got	      # address of GOT  */

static const bfd_byte elf_s390_plt_first_entry[PLT_FIRST_ENTRY_SIZE] =
  {
    0x50, 0x10, 0xf0, 0x1c,		      /* st	 %r1,28(%r15)	   */
    0x0d, 0x10,				      /* basr	 %r1,%r0	   */
    0x58, 0x10, 0x10, 0x12,		      /* l	 %r1,18(%r1)	   */
    0xd2, 0x03, 0xf0, 0x18, 0x10, 0x04,	      /* mvc	 24(4,%r15),4(%r1) */
    0x58, 0x10, 0x10, 0x08,		      /* l	 %r1,8(%r1)	   */
    0x07, 0xf1,				      /* br	 %r1		   */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
  };

static const bfd_byte elf_s390_plt_pic_first_entry[PLT_FIRST_ENTRY_SIZE] =
  {
    0x50, 0x10, 0xf0, 0x1c,			/* st	   %r1,28(%r15)	 */
    0x58, 0x10, 0xc0, 0x04,			/* l	   %r1,4(%r12)	 */
    0x50, 0x10, 0xf0, 0x18,			/* st	   %r1,24(%r15)	 */
    0x58, 0x10, 0xc0, 0x08,			/* l	   %r1,8(%r12)	 */
    0x07, 0xf1,					/* br	   %r1		 */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
  };


/* s390 ELF linker hash entry.  */

struct elf_s390_link_hash_entry
{
  struct elf_link_hash_entry elf;

  /* Number of GOTPLT references for a function.  */
  bfd_signed_vma gotplt_refcount;

#define GOT_UNKNOWN	0
#define GOT_NORMAL	1
#define GOT_TLS_GD	2
#define GOT_TLS_IE	3
#define GOT_TLS_IE_NLT	4
  unsigned char tls_type;

  /* For pointer equality reasons we might need to change the symbol
     type from STT_GNU_IFUNC to STT_FUNC together with its value and
     section entry.  So after alloc_dynrelocs only these values should
     be used.  In order to check whether a symbol is IFUNC use
     s390_is_ifunc_symbol_p.  */
  bfd_vma ifunc_resolver_address;
  asection *ifunc_resolver_section;
};

#define elf_s390_hash_entry(ent) \
  ((struct elf_s390_link_hash_entry *)(ent))

/* This structure represents an entry in the local PLT list needed for
   local IFUNC symbols.  */
struct plt_entry
{
  /* The section of the local symbol.
     Set in relocate_section and used in finish_dynamic_sections.  */
  asection *sec;

  union
  {
    bfd_signed_vma refcount;
    bfd_vma offset;
  } plt;
};

/* NOTE: Keep this structure in sync with
   the one declared in elf64-s390.c.  */
struct elf_s390_obj_tdata
{
  struct elf_obj_tdata root;

  /* A local PLT is needed for ifunc symbols.  */
  struct plt_entry *local_plt;

  /* TLS type for each local got entry.  */
  char *local_got_tls_type;
};

#define elf_s390_tdata(abfd) \
  ((struct elf_s390_obj_tdata *) (abfd)->tdata.any)

#define elf_s390_local_plt(abfd)		\
  (elf_s390_tdata (abfd)->local_plt)

#define elf_s390_local_got_tls_type(abfd) \
  (elf_s390_tdata (abfd)->local_got_tls_type)

#define is_s390_elf(bfd) \
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour \
   && elf_tdata (bfd) != NULL \
   && elf_object_id (bfd) == S390_ELF_DATA)

static bool
elf_s390_mkobject (bfd *abfd)
{
  if (abfd == NULL) {
    return false;
  }
  
  return bfd_elf_allocate_object (abfd, sizeof (struct elf_s390_obj_tdata));
}

static bool
elf_s390_object_p (bfd *abfd)
{
  if (abfd == NULL)
    return false;
    
  return bfd_default_set_arch_mach (abfd, bfd_arch_s390, bfd_mach_s390_31);
}

/* s390 ELF linker hash table.  */

struct elf_s390_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *irelifunc;

  union
  {
    bfd_signed_vma refcount;
    bfd_vma offset;
  } tls_ldm_got;
};

/* Get the s390 ELF linker hash table from a link_info structure.  */

#define elf_s390_hash_table(p) \
  ((is_elf_hash_table ((p)->hash)					\
    && elf_hash_table_id (elf_hash_table (p)) == S390_ELF_DATA)		\
   ? (struct elf_s390_link_hash_table *) (p)->hash : NULL)

#undef ELF64
#include "elf-s390-common.c"

/* Create an entry in an s390 ELF linker hash table.  */

static struct bfd_hash_entry *
link_hash_newfunc (struct bfd_hash_entry *entry,
		   struct bfd_hash_table *table,
		   const char *string)
{
  if (entry == NULL)
    {
      entry = bfd_hash_allocate (table,
				 sizeof (struct elf_s390_link_hash_entry));
      if (entry == NULL)
	return NULL;
    }

  entry = _bfd_elf_link_hash_newfunc (entry, table, string);
  if (entry == NULL)
    return NULL;

  struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry *) entry;
  eh->gotplt_refcount = 0;
  eh->tls_type = GOT_UNKNOWN;
  eh->ifunc_resolver_address = 0;
  eh->ifunc_resolver_section = NULL;

  return entry;
}

/* Create an s390 ELF linker hash table.  */

static struct bfd_link_hash_table *
elf_s390_link_hash_table_create (bfd *abfd)
{
  struct elf_s390_link_hash_table *ret;
  size_t amt = sizeof (struct elf_s390_link_hash_table);

  ret = (struct elf_s390_link_hash_table *) bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->elf, abfd, link_hash_newfunc,
                                      sizeof (struct elf_s390_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  return &ret->elf.root;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
elf_s390_copy_indirect_symbol (struct bfd_link_info *info,
			       struct elf_link_hash_entry *dir,
			       struct elf_link_hash_entry *ind)
{
  struct elf_s390_link_hash_entry *edir, *eind;

  if (!info || !dir || !ind)
    return;

  edir = (struct elf_s390_link_hash_entry *) dir;
  eind = (struct elf_s390_link_hash_entry *) ind;

  if (ind->root.type == bfd_link_hash_indirect && dir->got.refcount <= 0)
    {
      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
      return;
    }

  if (ELIMINATE_COPY_RELOCS &&
      ind->root.type != bfd_link_hash_indirect &&
      dir->dynamic_adjusted)
    {
      if (dir->versioned != versioned_hidden)
	dir->ref_dynamic |= ind->ref_dynamic;
      dir->ref_regular |= ind->ref_regular;
      dir->ref_regular_nonweak |= ind->ref_regular_nonweak;
      dir->needs_plt |= ind->needs_plt;
    }
  else
    {
      _bfd_elf_link_hash_copy_indirect (info, dir, ind);
    }
}

static int
elf_s390_tls_transition (struct bfd_link_info *info,
                        int r_type,
                        int is_local)
{
  if (bfd_link_pic (info))
    return r_type;

  switch (r_type)
    {
    case R_390_TLS_GD32:
    case R_390_TLS_IE32:
      return is_local ? R_390_TLS_LE32 : R_390_TLS_IE32;
    case R_390_TLS_GOTIE32:
      return is_local ? R_390_TLS_LE32 : R_390_TLS_GOTIE32;
    case R_390_TLS_LDM32:
      return R_390_TLS_LE32;
    default:
      return r_type;
    }
}

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bool
is_pc_relative_reloc(unsigned int r_type)
{
  return (r_type == R_390_PC16 || r_type == R_390_PC12DBL ||
          r_type == R_390_PC16DBL || r_type == R_390_PC24DBL ||
          r_type == R_390_PC32DBL || r_type == R_390_PC32);
}

static bool
requires_got_entry(unsigned int r_type)
{
  switch (r_type)
  {
    case R_390_GOT12:
    case R_390_GOT16:
    case R_390_GOT20:
    case R_390_GOT32:
    case R_390_GOTENT:
    case R_390_GOTPLT12:
    case R_390_GOTPLT16:
    case R_390_GOTPLT20:
    case R_390_GOTPLT32:
    case R_390_GOTPLTENT:
    case R_390_TLS_GD32:
    case R_390_TLS_GOTIE12:
    case R_390_TLS_GOTIE20:
    case R_390_TLS_GOTIE32:
    case R_390_TLS_IEENT:
    case R_390_TLS_IE32:
    case R_390_TLS_LDM32:
      return true;
    default:
      return false;
  }
}

static bool
requires_got_table(unsigned int r_type)
{
  return requires_got_entry(r_type) ||
         r_type == R_390_GOTOFF16 || r_type == R_390_GOTOFF32 ||
         r_type == R_390_GOTPC || r_type == R_390_GOTPCDBL;
}

static bool
requires_plt_entry(unsigned int r_type)
{
  switch (r_type)
  {
    case R_390_PLT12DBL:
    case R_390_PLT16DBL:
    case R_390_PLT24DBL:
    case R_390_PLT32DBL:
    case R_390_PLT32:
    case R_390_PLTOFF16:
    case R_390_PLTOFF32:
      return true;
    default:
      return false;
  }
}

static bool
requires_gotplt_entry(unsigned int r_type)
{
  switch (r_type)
  {
    case R_390_GOTPLT12:
    case R_390_GOTPLT16:
    case R_390_GOTPLT20:
    case R_390_GOTPLT32:
    case R_390_GOTPLTENT:
      return true;
    default:
      return false;
  }
}

static int
get_tls_type(unsigned int r_type)
{
  switch (r_type)
  {
    case R_390_TLS_GD32:
      return GOT_TLS_GD;
    case R_390_TLS_IE32:
    case R_390_TLS_GOTIE32:
      return GOT_TLS_IE;
    case R_390_TLS_GOTIE12:
    case R_390_TLS_GOTIE20:
    case R_390_TLS_IEENT:
      return GOT_TLS_IE_NLT;
    default:
      return GOT_NORMAL;
  }
}

static bool
handle_ifunc_symbol(struct elf_s390_link_hash_table *htab,
                    bfd *abfd,
                    struct bfd_link_info *info,
                    Elf_Internal_Shdr *symtab_hdr,
                    unsigned int r_symndx)
{
  struct plt_entry *plt;
  bfd_signed_vma *local_got_refcounts;

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;

  if (!s390_elf_create_ifunc_sections(htab->elf.dynobj, info))
    return false;

  local_got_refcounts = elf_local_got_refcounts(abfd);
  if (local_got_refcounts == NULL)
  {
    if (!elf_s390_allocate_local_syminfo(abfd, symtab_hdr))
      return false;
    local_got_refcounts = elf_local_got_refcounts(abfd);
  }

  plt = elf_s390_local_plt(abfd);
  plt[r_symndx].plt.refcount++;
  return true;
}

static bool
ensure_got_table_created(struct elf_s390_link_hash_table *htab,
                         bfd *abfd,
                         struct bfd_link_info *info)
{
  if (htab->elf.sgot != NULL)
    return true;

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;

  return _bfd_elf_create_got_section(htab->elf.dynobj, info);
}

static bool
needs_dynamic_reloc(struct bfd_link_info *info,
                    asection *sec,
                    struct elf_link_hash_entry *h,
                    unsigned int r_type)
{
  if (bfd_link_pic(info) && (sec->flags & SEC_ALLOC) != 0)
  {
    if (!is_pc_relative_reloc(r_type))
      return true;
    
    if (h != NULL && (!SYMBOLIC_BIND(info, h) ||
                      h->root.type == bfd_link_hash_defweak ||
                      !h->def_regular))
      return true;
  }

  if (ELIMINATE_COPY_RELOCS && !bfd_link_pic(info) &&
      (sec->flags & SEC_ALLOC) != 0 && h != NULL &&
      (h->root.type == bfd_link_hash_defweak || !h->def_regular))
    return true;

  return false;
}

static bool
elf_s390_check_relocs(bfd *abfd,
                      struct bfd_link_info *info,
                      asection *sec,
                      const Elf_Internal_Rela *relocs)
{
  struct elf_s390_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sreloc;
  bfd_signed_vma *local_got_refcounts;
  int tls_type, old_tls_type;
  Elf_Internal_Sym *isym;

  if (bfd_link_relocatable(info))
    return true;

  BFD_ASSERT(is_s390_elf(abfd));

  htab = elf_s390_hash_table(info);
  symtab_hdr = &elf_symtab_hdr(abfd);
  sym_hashes = elf_sym_hashes(abfd);
  local_got_refcounts = elf_local_got_refcounts(abfd);
  sreloc = NULL;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
  {
    unsigned int r_type;
    unsigned int r_symndx;
    struct elf_link_hash_entry *h;

    r_symndx = ELF32_R_SYM(rel->r_info);

    if (r_symndx >= NUM_SHDR_ENTRIES(symtab_hdr))
    {
      _bfd_error_handler(_("%pB: bad symbol index: %d"), abfd, r_symndx);
      return false;
    }

    if (r_symndx < symtab_hdr->sh_info)
    {
      isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
      if (isym == NULL)
        return false;

      if (ELF_ST_TYPE(isym->st_info) == STT_GNU_IFUNC)
      {
        if (!handle_ifunc_symbol(htab, abfd, info, symtab_hdr, r_symndx))
          return false;
      }
      h = NULL;
    }
    else
    {
      h = sym_hashes[r_symndx - symtab_hdr->sh_info];
      while (h->root.type == bfd_link_hash_indirect ||
             h->root.type == bfd_link_hash_warning)
        h = (struct elf_link_hash_entry *)h->root.u.i.link;
    }

    r_type = elf_s390_tls_transition(info, ELF32_R_TYPE(rel->r_info), h == NULL);

    if (requires_got_entry(r_type) && h == NULL && local_got_refcounts == NULL)
    {
      if (!elf_s390_allocate_local_syminfo(abfd, symtab_hdr))
        return false;
      local_got_refcounts = elf_local_got_refcounts(abfd);
    }

    if (requires_got_table(r_type))
    {
      if (!ensure_got_table_created(htab, abfd, info))
        return false;
    }

    if (h != NULL)
    {
      if (htab->elf.dynobj == NULL)
        htab->elf.dynobj = abfd;
      if (!s390_elf_create_ifunc_sections(htab->elf.dynobj, info))
        return false;

      if (s390_is_ifunc_symbol_p(h) && h->def_regular)
      {
        h->ref_regular = 1;
        h->needs_plt = 1;
      }
    }

    switch (r_type)
    {
      case R_390_GOTPC:
      case R_390_GOTPCDBL:
        break;

      case R_390_GOTOFF16:
      case R_390_GOTOFF32:
        if (h != NULL && s390_is_ifunc_symbol_p(h) && h->def_regular)
        {
          /* Fall through to PLT handling */
        }
        else
        {
          break;
        }

      case R_390_PLT12DBL:
      case R_390_PLT16DBL:
      case R_390_PLT24DBL:
      case R_390_PLT32DBL:
      case R_390_PLT32:
      case R_390_PLTOFF16:
      case R_390_PLTOFF32:
        if (h != NULL)
        {
          h->needs_plt = 1;
          h->plt.refcount += 1;
        }
        break;

      case R_390_GOTPLT12:
      case R_390_GOTPLT16:
      case R_390_GOTPLT20:
      case R_390_GOTPLT32:
      case R_390_GOTPLTENT:
        if (h != NULL)
        {
          ((struct elf_s390_link_hash_entry *)h)->gotplt_refcount++;
          h->needs_plt = 1;
          h->plt.refcount += 1;
        }
        else
        {
          local_got_refcounts[r_symndx] += 1;
        }
        break;

      case R_390_TLS_LDM32:
        htab->tls_ldm_got.refcount += 1;
        break;

      case R_390_TLS_IE32:
      case R_390_TLS_GOTIE12:
      case R_390_TLS_GOTIE20:
      case R_390_TLS_GOTIE32:
      case R_390_TLS_IEENT:
        if (bfd_link_pic(info))
          info->flags |= DF_STATIC_TLS;

      case R_390_GOT12:
      case R_390_GOT16:
      case R_390_GOT20:
      case R_390_GOT32:
      case R_390_GOTENT:
      case R_390_TLS_GD32:
        tls_type = get_tls_type(r_type);

        if (h != NULL)
        {
          h->got.refcount += 1;
          old_tls_type = elf_s390_hash_entry(h)->tls_type;
        }
        else
        {
          local_got_refcounts[r_symndx] += 1;
          old_tls_type = elf_s390_local_got_tls_type(abfd)[r_symndx];
        }

        if (old_tls_type != tls_type && old_tls_type != GOT_UNKNOWN)
        {
          if (old_tls_type == GOT_NORMAL || tls_type == GOT_NORMAL)
          {
            _bfd_error_handler(_("%pB: `%s' accessed both as normal and thread local symbol"),
                               abfd, h->root.root.string);
            return false;
          }
          if (old_tls_type > tls_type)
            tls_type = old_tls_type;
        }

        if (old_tls_type != tls_type)
        {
          if (h != NULL)
            elf_s390_hash_entry(h)->tls_type = tls_type;
          else
            elf_s390_local_got_tls_type(abfd)[r_symndx] = tls_type;
        }

        if (r_type != R_390_TLS_IE32)
          break;

      case R_390_TLS_LE32:
        if (r_type == R_390_TLS_LE32 && bfd_link_pie(info))
          break;

        if (!bfd_link_pic(info))
          break;
        info->flags |= DF_STATIC_TLS;

      case R_390_8:
      case R_390_16:
      case R_390_32:
      case R_390_PC16:
      case R_390_PC12DBL:
      case R_390_PC16DBL:
      case R_390_PC24DBL:
      case R_390_PC32DBL:
      case R_390_PC32:
        if (h != NULL && bfd_link_executable(info))
        {
          h->non_got_ref = 1;
          if (!bfd_link_pic(info))
            h->plt.refcount += 1;
        }

        if (needs_dynamic_reloc(info, sec, h, ELF32_R_TYPE(rel->r_info)))
        {
          struct elf_dyn_relocs *p;
          struct elf_dyn_relocs **head;

          if (sreloc == NULL)
          {
            if (htab->elf.dynobj == NULL)
              htab->elf.dynobj = abfd;

            sreloc = _bfd_elf_make_dynamic_reloc_section(sec, htab->elf.dynobj, 2, abfd, true);
            if (sreloc == NULL)
              return false;
          }

          if (h != NULL)
          {
            head = &h->dyn_relocs;
          }
          else
          {
            asection *s;
            void *vpp;

            isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
            if (isym == NULL)
              return false;

            s = bfd_section_from_elf_index(abfd, isym->st_shndx);
            if (s == NULL)
              s = sec;

            vpp = &elf_section_data(s)->local_dynrel;
            head = (struct elf_dyn_relocs **)vpp;
          }

          p = *head;
          if (p == NULL || p->sec != sec)
          {
            size_t amt = sizeof(*p);
            p = (struct elf_dyn_relocs *)bfd_alloc(htab->elf.dynobj, amt);
            if (p == NULL)
              return false;
            p->next = *head;
            *head = p;
            p->sec = sec;
            p->count = 0;
            p->pc_count = 0;
          }

          p->count += 1;
          if (is_pc_relative_reloc(ELF32_R_TYPE(rel->r_info)))
            p->pc_count += 1;
        }
        break;

      case R_390_GNU_VTINHERIT:
        if (!bfd_elf_gc_record_vtinherit(abfd, sec, h, rel->r_offset))
          return false;
        break;

      case R_390_GNU_VTENTRY:
        if (!bfd_elf_gc_record_vtentry(abfd, sec, h, rel->r_addend))
          return false;
        break;

      default:
        break;
    }
  }

  return true;
}

/* Return the section that should be marked against GC for a given
   relocation.  */

static asection *
elf_s390_gc_mark_hook (asection *sec,
		       struct bfd_link_info *info,
		       Elf_Internal_Rela *rel,
		       struct elf_link_hash_entry *h,
		       Elf_Internal_Sym *sym)
{
  if (h != NULL)
    {
      unsigned int r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_390_GNU_VTINHERIT || r_type == R_390_GNU_VTENTRY)
	return NULL;
    }
  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

/* Make sure we emit a GOT entry if the symbol was supposed to have a PLT
   entry but we found we will not create any.  Called when we find we will
   not have any PLT for this symbol, by for example
   elf_s390_adjust_dynamic_symbol when we're doing a proper dynamic link,
   or elf_s390_late_size_sections if no dynamic sections will be
   created (we're only linking static objects).  */

static void
elf_s390_adjust_gotplt (struct elf_s390_link_hash_entry *h)
{
  if (h == NULL)
    return;

  if (h->elf.root.type == bfd_link_hash_warning)
    h = (struct elf_s390_link_hash_entry *) h->elf.root.u.i.link;

  if (h == NULL || h->gotplt_refcount <= 0)
    return;

  h->elf.got.refcount += h->gotplt_refcount;
  h->gotplt_refcount = -1;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool
elf_s390_adjust_dynamic_symbol (struct bfd_link_info *info,
				struct elf_link_hash_entry *h)
{
  struct elf_s390_link_hash_table *htab;
  asection *s, *srel;

  if (s390_is_ifunc_symbol_p (h))
    {
      return handle_ifunc_symbol(info, h);
    }

  if (h->type == STT_FUNC || h->needs_plt)
    {
      return handle_function_symbol(info, h);
    }

  h->plt.offset = (bfd_vma) -1;

  if (h->is_weakalias)
    {
      return handle_weak_symbol(info, h);
    }

  if (bfd_link_pic (info))
    return true;

  if (!h->non_got_ref)
    return true;

  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return true;
    }

  if (ELIMINATE_COPY_RELOCS && !_bfd_elf_readonly_dynrelocs (h))
    {
      h->non_got_ref = 0;
      return true;
    }

  htab = elf_s390_hash_table (info);

  if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      s = htab->elf.sdynrelro;
      srel = htab->elf.sreldynrelro;
    }
  else
    {
      s = htab->elf.sdynbss;
      srel = htab->elf.srelbss;
    }
  
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      srel->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

static bool
handle_ifunc_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  if (h->ref_regular && SYMBOL_CALLS_LOCAL (info, h))
    {
      bfd_size_type pc_count = 0, count = 0;
      struct elf_dyn_relocs **pp;
      struct elf_dyn_relocs *p;

      for (pp = &h->dyn_relocs; (p = *pp) != NULL; )
        {
          pc_count += p->pc_count;
          p->count -= p->pc_count;
          p->pc_count = 0;
          count += p->count;
          if (p->count == 0)
            *pp = p->next;
          else
            pp = &p->next;
        }

      if (pc_count || count)
        {
          h->needs_plt = 1;
          h->non_got_ref = 1;
          if (h->plt.refcount <= 0)
            h->plt.refcount = 1;
          else
            h->plt.refcount += 1;
        }
    }

  if (h->plt.refcount <= 0)
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
    }
  return true;
}

static bool
handle_function_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  if (h->plt.refcount <= 0
      || SYMBOL_CALLS_LOCAL (info, h)
      || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
      elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *) h);
    }
  return true;
}

static bool
handle_weak_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  struct elf_link_hash_entry *def = weakdef (h);
  BFD_ASSERT (def->root.type == bfd_link_hash_defined);
  h->root.u.def.section = def->root.u.def.section;
  h->root.u.def.value = def->root.u.def.value;
  if (ELIMINATE_COPY_RELOCS || info->nocopyreloc)
    h->non_got_ref = def->non_got_ref;
  return true;
}

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bool
allocate_dynrelocs (struct elf_link_hash_entry *h, void * inf)
{
  struct bfd_link_info *info;
  struct elf_s390_link_hash_table *htab;
  struct elf_dyn_relocs *p;

  if (h->root.type == bfd_link_hash_indirect)
    return true;

  info = (struct bfd_link_info *) inf;
  htab = elf_s390_hash_table (info);

  if (htab == NULL)
    return false;

  if (s390_is_ifunc_symbol_p (h) && h->def_regular)
    return s390_elf_allocate_ifunc_dyn_relocs (info, h);

  if (htab->elf.dynamic_sections_created && h->plt.refcount > 0)
    {
      if (!allocate_plt_entry(info, h, htab))
        return false;
    }
  else
    {
      reset_plt_entry(h);
    }

  if (!allocate_got_entry(info, h, htab))
    return false;

  if (!process_dynamic_relocations(info, h, htab))
    return false;

  allocate_relocation_space(h);

  return true;
}

static bool
allocate_plt_entry(struct bfd_link_info *info, struct elf_link_hash_entry *h, 
                   struct elf_s390_link_hash_table *htab)
{
  if (h->dynindx == -1 && !h->forced_local)
    {
      if (!bfd_elf_link_record_dynamic_symbol (info, h))
        return false;
    }

  if (bfd_link_pic (info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, 0, h))
    {
      asection *s = htab->elf.splt;

      if (s->size == 0)
        s->size += PLT_FIRST_ENTRY_SIZE;

      h->plt.offset = s->size;

      if (!bfd_link_pic (info) && !h->def_regular)
        {
          h->root.u.def.section = s;
          h->root.u.def.value = h->plt.offset;
        }

      s->size += PLT_ENTRY_SIZE;
      htab->elf.sgotplt->size += GOT_ENTRY_SIZE;
      htab->elf.srelplt->size += sizeof (Elf32_External_Rela);
    }
  else
    {
      reset_plt_entry(h);
    }

  return true;
}

static void
reset_plt_entry(struct elf_link_hash_entry *h)
{
  h->plt.offset = (bfd_vma) -1;
  h->needs_plt = 0;
  elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *) h);
}

static bool
allocate_got_entry(struct bfd_link_info *info, struct elf_link_hash_entry *h,
                   struct elf_s390_link_hash_table *htab)
{
  if (h->got.refcount <= 0)
    {
      h->got.offset = (bfd_vma) -1;
      return true;
    }

  struct elf_s390_link_hash_entry *s390_h = elf_s390_hash_entry(h);
  int tls_type = s390_h->tls_type;

  if (!bfd_link_pic (info) && h->dynindx == -1 && tls_type >= GOT_TLS_IE)
    {
      if (tls_type == GOT_TLS_IE_NLT)
        {
          h->got.offset = htab->elf.sgot->size;
          htab->elf.sgot->size += GOT_ENTRY_SIZE;
        }
      else
        {
          h->got.offset = (bfd_vma) -1;
        }
      return true;
    }

  if (h->dynindx == -1 && !h->forced_local)
    {
      if (!bfd_elf_link_record_dynamic_symbol (info, h))
        return false;
    }

  asection *s = htab->elf.sgot;
  h->got.offset = s->size;
  s->size += GOT_ENTRY_SIZE;

  if (tls_type == GOT_TLS_GD)
    s->size += GOT_ENTRY_SIZE;

  allocate_got_relocations(info, h, htab, tls_type);

  return true;
}

static void
allocate_got_relocations(struct bfd_link_info *info, struct elf_link_hash_entry *h,
                         struct elf_s390_link_hash_table *htab, int tls_type)
{
  bool dyn = htab->elf.dynamic_sections_created;

  if ((tls_type == GOT_TLS_GD && h->dynindx == -1) || tls_type >= GOT_TLS_IE)
    {
      htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
    }
  else if (tls_type == GOT_TLS_GD)
    {
      htab->elf.srelgot->size += 2 * sizeof (Elf32_External_Rela);
    }
  else if (!UNDEFWEAK_NO_DYNAMIC_RELOC (info, h) &&
           (bfd_link_pic (info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, 0, h)))
    {
      htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
    }
}

static bool
process_dynamic_relocations(struct bfd_link_info *info, struct elf_link_hash_entry *h,
                           struct elf_s390_link_hash_table *htab)
{
  if (h->dyn_relocs == NULL)
    return true;

  if (bfd_link_pic (info))
    return process_shared_relocations(info, h);
  else if (ELIMINATE_COPY_RELOCS)
    return process_nonshared_relocations(info, h, htab);

  return true;
}

static bool
process_shared_relocations(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  if (SYMBOL_CALLS_LOCAL (info, h))
    {
      struct elf_dyn_relocs **pp;
      struct elf_dyn_relocs *p;

      for (pp = &h->dyn_relocs; (p = *pp) != NULL; )
        {
          p->count -= p->pc_count;
          p->pc_count = 0;
          if (p->count == 0)
            *pp = p->next;
          else
            pp = &p->next;
        }
    }

  if (h->dyn_relocs != NULL && h->root.type == bfd_link_hash_undefweak)
    {
      if (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
        {
          h->dyn_relocs = NULL;
        }
      else if (h->dynindx == -1 && !h->forced_local)
        {
          if (!bfd_elf_link_record_dynamic_symbol (info, h))
            return false;
        }
    }

  return true;
}

static bool
process_nonshared_relocations(struct bfd_link_info *info, struct elf_link_hash_entry *h,
                              struct elf_s390_link_hash_table *htab)
{
  if (!h->non_got_ref &&
      ((h->def_dynamic && !h->def_regular) ||
       (htab->elf.dynamic_sections_created &&
        (h->root.type == bfd_link_hash_undefweak || h->root.type == bfd_link_hash_undefined))))
    {
      if (h->dynindx == -1 && !h->forced_local)
        {
          if (!bfd_elf_link_record_dynamic_symbol (info, h))
            return false;
        }

      if (h->dynindx != -1)
        return true;
    }

  h->dyn_relocs = NULL;
  return true;
}

static void
allocate_relocation_space(struct elf_link_hash_entry *h)
{
  struct elf_dyn_relocs *p;

  for (p = h->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (Elf32_External_Rela);
    }
}

/* Set the sizes of the dynamic sections.  */

static bool
elf_s390_late_size_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
			     struct bfd_link_info *info)
{
  struct elf_s390_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bool relocs;
  bfd *ibfd;

  htab = elf_s390_hash_table (info);
  if (!htab)
    return false;
  
  dynobj = htab->elf.dynobj;
  if (dynobj == NULL)
    return true;

  if (htab->elf.dynamic_sections_created)
    {
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  s = bfd_get_linker_section (dynobj, ".interp");
	  if (s == NULL)
	    return false;
	  s->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
	  s->alloced = 1;
	}
    }

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      char *local_tls_type;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srela;
      struct plt_entry *local_plt;
      unsigned int i;

      if (! is_s390_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = elf_section_data (s)->local_dynrel; p != NULL; p = p->next)
	    {
	      if (bfd_is_abs_section (p->sec) ||
		  bfd_is_abs_section (p->sec->output_section))
		{
		  continue;
		}
	      
	      if (p->count != 0)
		{
		  srela = elf_section_data (p->sec)->sreloc;
		  if (!srela)
		    return false;
		  srela->size += p->count * sizeof (Elf32_External_Rela);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      local_tls_type = elf_s390_local_got_tls_type (ibfd);
      s = htab->elf.sgot;
      srela = htab->elf.srelgot;
      
      for (; local_got < end_local_got; ++local_got, ++local_tls_type)
	{
	  if (*local_got > 0)
	    {
	      *local_got = s->size;
	      s->size += GOT_ENTRY_SIZE;
	      if (*local_tls_type == GOT_TLS_GD)
		s->size += GOT_ENTRY_SIZE;
	      if (bfd_link_pic (info))
		srela->size += sizeof (Elf32_External_Rela);
	    }
	  else
	    *local_got = (bfd_vma) -1;
	}
      
      local_plt = elf_s390_local_plt (ibfd);
      if (!local_plt)
	continue;
	
      for (i = 0; i < symtab_hdr->sh_info; i++)
	{
	  if (local_plt[i].plt.refcount > 0)
	    {
	      local_plt[i].plt.offset = htab->elf.iplt->size;
	      htab->elf.iplt->size += PLT_ENTRY_SIZE;
	      htab->elf.igotplt->size += GOT_ENTRY_SIZE;
	      htab->elf.irelplt->size += RELA_ENTRY_SIZE;
	    }
	  else
	    local_plt[i].plt.offset = (bfd_vma) -1;
	}
    }

  if (htab->tls_ldm_got.refcount > 0)
    {
      htab->tls_ldm_got.offset = htab->elf.sgot->size;
      htab->elf.sgot->size += 2 * GOT_ENTRY_SIZE;
      htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
    }
  else
    htab->tls_ldm_got.offset = -1;

  elf_link_hash_traverse (&htab->elf, allocate_dynrelocs, info);

  relocs = false;
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (s == htab->elf.splt ||
	  s == htab->elf.sgot ||
	  s == htab->elf.sgotplt ||
	  s == htab->elf.sdynbss ||
	  s == htab->elf.sdynrelro ||
	  s == htab->elf.iplt ||
	  s == htab->elf.igotplt ||
	  s == htab->irelifunc)
	{
	  /* Handled sections - continue processing */
	}
      else if (startswith (bfd_section_name (s), ".rela"))
	{
	  if (s->size != 0)
	    relocs = true;
	  s->reloc_count = 0;
	}
      else
	{
	  continue;
	}

      if (s->size == 0)
	{
	  s->flags |= SEC_EXCLUDE;
	  continue;
	}

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
	continue;

      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	return false;
      s->alloced = 1;
    }

  return _bfd_elf_add_dynamic_tags (output_bfd, info, relocs);
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving @dtpoff relocation.
   This is PT_TLS segment p_vaddr.  */

static bfd_vma
dtpoff_base (struct bfd_link_info *info)
{
  struct elf_link_hash_table *hash_table;
  
  if (info == NULL)
    return 0;
    
  hash_table = elf_hash_table (info);
  if (hash_table == NULL || hash_table->tls_sec == NULL)
    return 0;
    
  return hash_table->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
tpoff (struct bfd_link_info *info, bfd_vma address)
{
  struct elf_link_hash_table *htab;
  
  if (info == NULL)
    return 0;
    
  htab = elf_hash_table (info);
  if (htab == NULL || htab->tls_sec == NULL)
    return 0;
    
  return htab->tls_size + htab->tls_sec->vma - address;
}

/* Complain if TLS instruction relocation is against an invalid
   instruction.  */

static void
invalid_tls_insn (bfd *input_bfd,
		  asection *input_section,
		  Elf_Internal_Rela *rel)
{
  reloc_howto_type *howto;
  unsigned int r_type;

  if (!input_bfd || !input_section || !rel) {
    bfd_set_error (bfd_error_invalid_operation);
    return;
  }

  r_type = ELF32_R_TYPE (rel->r_info);
  if (r_type >= sizeof(elf_howto_table) / sizeof(elf_howto_table[0])) {
    bfd_set_error (bfd_error_bad_value);
    return;
  }

  howto = &elf_howto_table[r_type];
  if (!howto || !howto->name) {
    bfd_set_error (bfd_error_bad_value);
    return;
  }

  _bfd_error_handler
    (_("%pB(%pA+%#" PRIx64 "): invalid instruction for TLS relocation %s"),
     input_bfd,
     input_section,
     (uint64_t) rel->r_offset,
     howto->name);
  bfd_set_error (bfd_error_bad_value);
}

/* Relocate a 390 ELF section.  */

static int
elf_s390_relocate_section (bfd *output_bfd,
			   struct bfd_link_info *info,
			   bfd *input_bfd,
			   asection *input_section,
			   bfd_byte *contents,
			   Elf_Internal_Rela *relocs,
			   Elf_Internal_Sym *local_syms,
			   asection **local_sections)
{
  struct elf_s390_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma *local_got_offsets;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;

  if (!is_s390_elf (input_bfd))
    {
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

  htab = elf_s390_hash_table (info);
  if (htab == NULL)
    return false;

  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);
  local_got_offsets = elf_local_got_offsets (input_bfd);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      unsigned int r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sec;
      bfd_vma off;
      bfd_vma relocation;
      bool unresolved_reloc;
      bfd_reloc_status_type r;
      int tls_type;
      asection *base_got = htab->elf.sgot;
      bool resolved_to_zero;

      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == (int) R_390_GNU_VTINHERIT
	  || r_type == (int) R_390_GNU_VTENTRY)
	continue;
      if (r_type >= (int) R_390_max)
	{
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}

      howto = elf_howto_table + r_type;
      r_symndx = ELF32_R_SYM (rel->r_info);

      h = NULL;
      sym = NULL;
      sec = NULL;
      unresolved_reloc = false;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  if (ELF_ST_TYPE (sym->st_info) == STT_GNU_IFUNC)
	    {
	      struct plt_entry *local_plt = elf_s390_local_plt (input_bfd);
	      if (local_plt == NULL)
		return false;

	      relocation = (htab->elf.iplt->output_section->vma
			    + htab->elf.iplt->output_offset
			    + local_plt[r_symndx].plt.offset);

	      switch (r_type)
		{
		case R_390_PLTOFF16:
		case R_390_PLTOFF32:
		  if (htab->elf.sgot == NULL)
		    return false;
		  relocation -= htab->elf.sgot->output_section->vma;
		  break;
		case R_390_GOTPLT12:
		case R_390_GOTPLT16:
		case R_390_GOTPLT20:
		case R_390_GOTPLT32:
		case R_390_GOTPLTENT:
		case R_390_GOT12:
		case R_390_GOT16:
		case R_390_GOT20:
		case R_390_GOT32:
		case R_390_GOTENT:
		  {
		    if (htab->elf.sgot == NULL || local_got_offsets == NULL)
		      return false;

		    bfd_put_32 (output_bfd, relocation,
				htab->elf.sgot->contents +
				local_got_offsets[r_symndx]);
		    relocation = (local_got_offsets[r_symndx] +
				  htab->elf.sgot->output_offset);

		    if (r_type == R_390_GOTENT || r_type == R_390_GOTPLTENT)
		      relocation += htab->elf.sgot->output_section->vma;
		    break;
		  }
		default:
		  break;
		}
	      local_plt[r_symndx].sec = sec;
	      goto do_relocation;
	    }
	  else
	    relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  bool warned ATTRIBUTE_UNUSED;
	  bool ignored ATTRIBUTE_UNUSED;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, R_390_NONE,
					 howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      resolved_to_zero = (h != NULL
			  && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));

      switch (r_type)
	{
	case R_390_GOTPLT12:
	case R_390_GOTPLT16:
	case R_390_GOTPLT20:
	case R_390_GOTPLT32:
	case R_390_GOTPLTENT:
	  if (h != NULL && h->plt.offset != (bfd_vma) -1)
	    {
	      bfd_vma plt_index;

	      if (s390_is_ifunc_symbol_p (h))
		{
		  if (htab->elf.igotplt == NULL)
		    return false;
		  plt_index = h->plt.offset / PLT_ENTRY_SIZE;
		  relocation = (plt_index * GOT_ENTRY_SIZE +
				htab->elf.igotplt->output_offset);
		  if (r_type == R_390_GOTPLTENT)
		    relocation += htab->elf.igotplt->output_section->vma;
		}
	      else
		{
		  if (htab->elf.sgot == NULL)
		    return false;
		  plt_index = (h->plt.offset - PLT_FIRST_ENTRY_SIZE) /
		    PLT_ENTRY_SIZE;

		  relocation = (plt_index + 3) * GOT_ENTRY_SIZE;
		  if (r_type == R_390_GOTPLTENT)
		    relocation += htab->elf.sgot->output_section->vma;
		}
	      unresolved_reloc = false;

	    }

	case R_390_GOT12:
	case R_390_GOT16:
	case R_390_GOT20:
	case R_390_GOT32:
	case R_390_GOTENT:
	  if (base_got == NULL)
	    return false;

	  if (h != NULL)
	    {
	      bool dyn;

	      off = h->got.offset;
	      dyn = htab->elf.dynamic_sections_created;

	      if (s390_is_ifunc_symbol_p (h))
		{
		  if (h->plt.offset == (bfd_vma) -1)
		    return false;
		  if (off == (bfd_vma)-1)
		    {
		      if (htab->elf.igotplt == NULL)
			return false;
		      base_got = htab->elf.igotplt;
		      off = h->plt.offset / PLT_ENTRY_SIZE * GOT_ENTRY_SIZE;
		    }
		}
	      else if (! WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn,
							  bfd_link_pic (info),
							  h)
		       || SYMBOL_REFERENCES_LOCAL (info, h)
		       || resolved_to_zero)
		{
		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      bfd_put_32 (output_bfd, relocation,
				  base_got->contents + off);
		      h->got.offset |= 1;
		    }

		  if ((h->def_regular
		       && SYMBOL_REFERENCES_LOCAL (info, h))
		      && ((r_type == R_390_GOTENT
			   && (bfd_get_16 (input_bfd,
					   contents + rel->r_offset - 2)
			       & 0xff0f) == 0xc40d)
			  || (r_type == R_390_GOT20
			      && (bfd_get_32 (input_bfd,
					      contents + rel->r_offset - 2)
				  & 0xff00f000) == 0xe300c000
			      && bfd_get_8 (input_bfd,
					    contents + rel->r_offset + 3) == 0x58)))
		    {
		      unsigned short new_insn =
			(0xc000 | (bfd_get_8 (input_bfd,
					      contents + rel->r_offset - 1) & 0xf0));
		      bfd_put_16 (output_bfd, new_insn,
				  contents + rel->r_offset - 2);
		      r_type = R_390_PC32DBL;
		      rel->r_addend = 2;
		      howto = elf_howto_table + r_type;
		      relocation = h->root.u.def.value
			+ h->root.u.def.section->output_section->vma
			+ h->root.u.def.section->output_offset;
		      goto do_relocation;
		    }
		}
	      else
		unresolved_reloc = false;
	    }
	  else
	    {
	      if (local_got_offsets == NULL)
		return false;

	      off = local_got_offsets[r_symndx];

	      if ((off & 1) != 0)
		off &= ~1;
	      else
		{
		  if (htab->elf.sgot == NULL)
		    return false;
		  bfd_put_32 (output_bfd, relocation,
			      htab->elf.sgot->contents + off);

		  if (bfd_link_pic (info))
		    {
		      asection *srelgot;
		      Elf_Internal_Rela outrel;
		      bfd_byte *loc;

		      srelgot = htab->elf.srelgot;
		      if (srelgot == NULL)
			return false;

		      outrel.r_offset = (htab->elf.sgot->output_section->vma
					 + htab->elf.sgot->output_offset
					 + off);
		      outrel.r_info = ELF32_R_INFO (0, R_390_RELATIVE);
		      outrel.r_addend = relocation;
		      loc = srelgot->contents;
		      loc += srelgot->reloc_count++ * sizeof (Elf32_External_Rela);
		      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
		    }

		  local_got_offsets[r_symndx] |= 1;
		}
	    }

	  if (off >= (bfd_vma) -2)
	    return false;

	  relocation = base_got->output_offset + off;

	  if (   r_type == R_390_GOTENT
	      || r_type == R_390_GOTPLTENT)
	    relocation += base_got->output_section->vma;

	  break;

	case R_390_GOTOFF16:
	case R_390_GOTOFF32:
	  if (h != NULL
	      && s390_is_ifunc_symbol_p (h)
	      && h->def_regular
	      && !bfd_link_executable (info))
	    {
	      if (htab->elf.iplt == NULL || htab->elf.sgot == NULL)
		return false;
	      relocation = (htab->elf.iplt->output_section->vma
			    + htab->elf.iplt->output_offset
			    + h->plt.offset
			    - htab->elf.sgot->output_section->vma);
	      goto do_relocation;
	    }

	  if (htab->elf.sgot == NULL)
	    return false;
	  relocation -= htab->elf.sgot->output_section->vma;
	  break;

	case R_390_GOTPC:
	case R_390_GOTPCDBL:
	  if (htab->elf.sgot == NULL)
	    return false;
	  relocation = htab->elf.sgot->output_section->vma;
	  unresolved_reloc = false;
	  break;

	case R_390_PLT12DBL:
	case R_390_PLT16DBL:
	case R_390_PLT24DBL:
	case R_390_PLT32DBL:
	case R_390_PLT32:
	  if (h == NULL)
	    break;

	  if (h->plt.offset == (bfd_vma) -1
	      || (htab->elf.splt == NULL && htab->elf.iplt == NULL))
	    {
	      break;
	    }

	  if (s390_is_ifunc_symbol_p (h))
	    {
	      if (htab->elf.iplt == NULL)
		return false;
	      relocation = (htab->elf.iplt->output_section->vma
			    + htab->elf.iplt->output_offset
			    + h->plt.offset);
	    }
	  else
	    {
	      if (htab->elf.splt == NULL)
		return false;
	      relocation = (htab->elf.splt->output_section->vma
			    + htab->elf.splt->output_offset
			    + h->plt.offset);
	    }
	  unresolved_reloc = false;
	  break;

	case R_390_PLTOFF16:
	case R_390_PLTOFF32:
	  if (h == NULL
	      || h->plt.offset == (bfd_vma) -1
	      || (htab->elf.splt == NULL && !s390_is_ifunc_symbol_p (h)))
	    {
	      if (htab->elf.sgot == NULL)
		return false;
	      relocation -= htab->elf.sgot->output_section->vma;
	      break;
	    }

	  if (htab->elf.sgot == NULL)
	    return false;

	  if (s390_is_ifunc_symbol_p (h))
	    {
	      if (htab->elf.iplt == NULL)
		return false;
	      relocation = (htab->elf.iplt->output_section->vma
			    + htab->elf.iplt->output_offset
			    + h->plt.offset
			    - htab->elf.sgot->output_section->vma);
	    }
	  else
	    {
	      if (htab->elf.splt == NULL)
		return false;
	      relocation = (htab->elf.splt->output_section->vma
			    + htab->elf.splt->output_offset
			    + h->plt.offset
			    - htab->elf.sgot->output_section->vma);
	    }
	  unresolved_reloc = false;
	  break;

	case R_390_PC16:
	case R_390_PC12DBL:
	case R_390_PC16DBL:
	case R_390_PC24DBL:
	case R_390_PC32DBL:
	case R_390_PC32:
	  if (h != NULL
	      && s390_is_ifunc_symbol_p (h)
	      && h->def_regular
	      && !bfd_link_executable (info))
	    {
	      if (htab->elf.iplt == NULL)
		return false;
	      relocation = (htab->elf.iplt->output_section->vma
			    + htab->elf.iplt->output_offset
			    + h ->plt.offset);
	      goto do_relocation;
	    }

	case R_390_8:
	case R_390_16:
	case R_390_32:
	  if ((input_section->flags & SEC_ALLOC) == 0)
	    break;

	  if (h != NULL
	      && s390_is_ifunc_symbol_p (h)
	      && h->def_regular)
	    {
	      if (!bfd_link_pic (info))
		{
		  if (htab->elf.iplt == NULL)
		    return false;
		  relocation = (htab->elf.iplt->output_section->vma
				+ htab->elf.iplt->output_offset
				+ h ->plt.offset);
		  goto do_relocation;
		}
	      else
		{
		  Elf_Internal_Rela outrel;
		  asection *sreloc;

		  outrel.r_offset = _bfd_elf_section_offset (output_bfd,
							     info,
							     input_section,
							     rel->r_offset);
		  if (outrel.r_offset == (bfd_vma) -1
		      || outrel.r_offset == (bfd_vma) -2)
		    return false;

		  outrel.r_offset += (input_section->output_section->vma
				      + input_section->output_offset);

		  if (h->dynindx == -1
		      || h->forced_local
		      || bfd_link_executable (info))
		    {
		      outrel.r_info = ELF32_R_INFO (0, R_390_IRELATIVE);
		      outrel.r_addend = (h->root.u.def.value
					 + h->root.u.def.section->output_section->vma
					 + h->root.u.def.section->output_offset);
		    }
		  else
		    {
		      outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
		      outrel.r_addend = 0;
		    }

		  sreloc = htab->elf.irelifunc;
		  if (sreloc == NULL)
		    return false;
		  elf_append_rela (output_bfd, sreloc, &outrel);

		  continue;
		}
	    }

	  if ((bfd_link_pic (info)
	       && (h == NULL
		   || (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		       && !resolved_to_zero)
		   || h->root.type != bfd_link_hash_undefweak)
	       && ((r_type != R_390_PC16
		    && r_type != R_390_PC12DBL
		    && r_type != R_390_PC16DBL
		    && r_type != R_390_PC24DBL
		    && r_type != R_390_PC32DBL
		    && r_type != R_390_PC32)
		   || !SYMBOL_CALLS_LOCAL (info, h)))
	      || (ELIMINATE_COPY_RELOCS
		  && !bfd_link_pic (info)
		  && h != NULL
		  && h->dynindx != -1
		  && !h->non_got_ref
		  && ((h->def_dynamic
		       && !h->def_regular)
		      || h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined)))
	    {
	      Elf_Internal_Rela outrel;
	      bool skip, relocate;
	      asection *sreloc;
	      bfd_byte *loc;

	      skip = false;
	      relocate = false;

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);
	      if (outrel.r_offset == (bfd_vma) -1)
		skip = true;
	      else if (outrel.r_offset == (bfd_vma) -2)
		skip = true, relocate = true;
	      outrel.r_offset += (input_section->output_section->vma
				  + input_section->output_offset);

	      if (skip)
		memset (&outrel, 0, sizeof outrel);
	      else if (h != NULL
		       && h->dynindx != -1
		       && (r_type == R_390_PC16
			   || r_type == R_390_PC12DBL
			   || r_type == R_390_PC16DBL
			   || r_type == R_390_PC24DBL
			   || r_type == R_390_PC32DBL
			   || r_type == R_390_PC32
			   || !bfd_link_pic (info)
			   || !SYMBOLIC_BIND (info, h)
			   || !h->def_regular))
		{
		  outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
		  outrel.r_addend = rel->r_addend;
		}
	      else
		{
		  outrel.r_addend = relocation + rel->r_addend;
		  if (r_type == R_390_32)
		    {
		      relocate = true;
		      outrel.r_info = ELF32_R_INFO (0, R_390_RELATIVE);
		    }
		  else
		    {
		      long sindx;

		      if (bfd_is_abs_section (sec))
			sindx = 0;
		      else if (sec == NULL || sec->owner == NULL)
			{
			  bfd_set_error(bfd_error_bad_value);
			  return false;
			}
		      else
			{
			  asection *osec;

			  osec = sec->output_section;
			  sindx = elf_section_data (osec)->dynindx;
			  if (sindx == 0)
			    {
			      osec = htab->elf.text_index_section;
			      if (osec == NULL)
				return false;
			      sindx = elf_section_data (osec)->dynindx;
			    }
			  if (sindx == 0)
			    return false;

			  outrel.r_addend -= osec->vma;
			}
		      outrel.r_info = ELF32_R_INFO (sindx, r_type);
		    }
		}

	      sreloc = elf_section_data (input_section)->sreloc;
	      if (sreloc == NULL)
		return false;

	      loc = sreloc->contents;
	      loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
	      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);

	      if (! relocate)
		continue;
	    }
	  break;

	case R_390_TLS_IE32:
	  if (bfd_link_pic (info))
	    {
	      Elf_Internal_Rela outrel;
	      asection *sreloc;
	      bfd_byte *loc;

	      outrel.r_offset = rel->r_offset
				+ input_section->output_section->vma
				+ input_section->output_offset;
	      outrel.r_info = ELF32_R_INFO (0, R_390_RELATIVE);
	      sreloc = elf_section_data (input_section)->sreloc;
	      if (sreloc == NULL)
		return false;
	      loc = sreloc->contents;
	      loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
	      bfd_elf32_swap_reloc_out (output_bfd, &outrel, loc);
	    }

	case R_390_TLS_GD32:
	case R_390_TLS_GOTIE32:
	  r_type = elf_s390_tls_transition (info, r_type, h == NULL);
	  tls_type = GOT_UNKNOWN;
	  if (h == NULL && local_got_offsets)
	    tls_type = elf_s390_local_got_tls_type (input_bfd) [r_symndx];
	  else if (h != NULL)
	    {
	      tls_type = elf_s390_hash_entry(h)->tls_type;
	      if (!bfd_link_pic (info)
		  && h->dynindx == -1
		  && tls_type >= GOT_TLS_IE)
		r_type = R_390_TLS_LE32;
	    }
	  if (r_type == R_390_TLS_GD32 && tls_type >= GOT_TLS_IE)
	    r_type = R_390_TLS_IE32;

	  if (r_type == R_390_TLS_LE32)
	    {
	      if (!unresolved_reloc)
		{
		  bfd_put_32 (output_bfd, -tpoff (info, relocation) + rel->r_addend,
			      contents + rel->r_offset);
		}
	      continue;
	    }

	  if (htab->elf.sgot == NULL)
	    return false;

	  if (h != NULL)
	    off = h->got.offset;
	  else
	    {
	      if (local_got_offsets == NULL)
		return false;

	      off = local_got_offsets[r_symndx];
	    }

	emit_tls_relocs:

	  if ((off & 1) != 0)
	    off &= ~1;
	  else
	    {
	      Elf_Internal_Rela outrel;
	      bfd_byte *loc;
	      int dr_type, indx;

	      if (htab->elf.srelgot == NULL)
		return false;

	      outrel.r_offset = (htab->elf.sgot->output_section->vma
				 + htab->elf.sgot->output_offset + off);

	      indx = h && h->dynindx != -1 ? h->dynindx : 0;
	      if (r_type == R_390_TLS_GD32)
		dr_type = R_390_TLS_DTPMOD;
	      else
		dr_type = R_390_TLS_TPOFF;
	      if (dr_type == R_390_TLS_TPOFF && indx == 0)
		outrel.r_addend = relocation - dtpoff_base (info);
	      else
		outrel.r_addend = 0;
	      outrel.r_info = ELF32_R_INFO (indx, dr_type);
	      loc = htab->elf.srelgot->contents;
	      loc += htab->elf.srelgot->reloc_count++
		* sizeof (Elf32_External_Rela);
	      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);

	      if (r_type == R_390_TLS_GD32)
		{
		  if (indx == 0)
		    {
		      if (!unresolved_reloc)
			{
			  bfd_put_32 (output_bfd,
				      relocation - dtpoff_base (info),
				      htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
			}
		    }
		  else
		    {
		      outrel.r_info = ELF32_R_INFO (indx, R_390_TLS_DTPOFF);
		      outrel.r_offset += GOT_ENTRY_SIZE;
		      outrel.r_addend = 0;
		      htab->elf.srelgot->reloc_count++;
		      loc += sizeof (Elf32_External_Rela);
		      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
		    }
		}

	      if (h != NULL)
		h->got.offset |= 1;
	      else
		local_got_offsets[r_symndx] |= 1;
	    }

	  if (off >= (bfd_vma) -2)
	    return false;
	  if (r_type == ELF32_R_TYPE (rel->r_info))
	    {
	      relocation = htab->elf.sgot->output_offset + off;
	      if (r_type == R_390_TLS_IE32 || r_type == R_390_TLS_IEENT)
		relocation += htab->elf.sgot->output_section->vma;
	      unresolved_reloc = false;
	    }
	  else
	    {
	      bfd_put_32 (output_bfd, htab->elf.sgot->output_offset + off,
			  contents + rel->r_offset);
	      continue;
	    }
	  break;

	case R_390_TLS_GOTIE12:
	case R_390_TLS_GOTIE20:
	case R_390_TLS_IEENT:
	  if (h == NULL)
	    {
	      if (local_got_offsets == NULL)
		return false;
	      off = local_got_offsets[r_symndx];
	      if (bfd_link_pic (info))
		goto emit

/* Generate the PLT slots together with the dynamic relocations needed
   for IFUNC symbols.  */

static void
elf_s390_finish_ifunc_symbol (bfd *output_bfd,
                              struct bfd_link_info *info,
                              struct elf_link_hash_entry *h,
                              struct elf_s390_link_hash_table *htab,
                              bfd_vma iplt_offset,
                              bfd_vma resolver_address)
{
  bfd_vma iplt_index;
  bfd_vma got_offset;
  bfd_vma igotiplt_offset;
  Elf_Internal_Rela rela;
  bfd_byte *loc;
  asection *plt, *gotplt, *relplt;
  bfd_vma relative_offset;

  if (htab->elf.iplt == NULL || htab->elf.igotplt == NULL || htab->elf.irelplt == NULL)
    abort ();

  gotplt = htab->elf.igotplt;
  relplt = htab->elf.irelplt;
  plt = htab->elf.iplt;

  iplt_index = iplt_offset / PLT_ENTRY_SIZE;
  igotiplt_offset = iplt_index * GOT_ENTRY_SIZE;
  got_offset = igotiplt_offset + gotplt->output_offset;

  relative_offset = -(plt->output_offset + (PLT_ENTRY_SIZE * iplt_index) + 18) / 2;
  if (-32768 > (int) relative_offset)
    relative_offset = -(unsigned) (((65536 / PLT_ENTRY_SIZE - 1) * PLT_ENTRY_SIZE) / 2);

  if (!bfd_link_pic (info)) {
    memcpy (plt->contents + iplt_offset, elf_s390_plt_entry, PLT_ENTRY_SIZE);
    bfd_put_32 (output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
    bfd_put_32 (output_bfd, gotplt->output_section->vma + got_offset,
                plt->contents + iplt_offset + 24);
  } else if (got_offset < 4096) {
    memcpy (plt->contents + iplt_offset, elf_s390_plt_pic12_entry, PLT_ENTRY_SIZE);
    bfd_put_16 (output_bfd, 0xc000 | got_offset, plt->contents + iplt_offset + 2);
    bfd_put_32 (output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
  } else if (got_offset < 32768) {
    memcpy (plt->contents + iplt_offset, elf_s390_plt_pic16_entry, PLT_ENTRY_SIZE);
    bfd_put_16 (output_bfd, got_offset, plt->contents + iplt_offset + 2);
    bfd_put_32 (output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
  } else {
    memcpy (plt->contents + iplt_offset, elf_s390_plt_pic_entry, PLT_ENTRY_SIZE);
    bfd_put_32 (output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
    bfd_put_32 (output_bfd, got_offset, plt->contents + iplt_offset + 24);
  }

  bfd_put_32 (output_bfd, relplt->output_offset + iplt_index * RELA_ENTRY_SIZE,
              plt->contents + iplt_offset + 28);

  bfd_put_32 (output_bfd, plt->output_section->vma + plt->output_offset + iplt_offset + 12,
              gotplt->contents + igotiplt_offset);

  rela.r_offset = gotplt->output_section->vma + got_offset;

  if (!h || h->dynindx == -1 ||
      ((bfd_link_executable (info) || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT) && h->def_regular)) {
    rela.r_info = ELF32_R_INFO (0, R_390_IRELATIVE);
    rela.r_addend = resolver_address;
  } else {
    rela.r_info = ELF32_R_INFO (h->dynindx, R_390_JMP_SLOT);
    rela.r_addend = 0;
  }

  loc = relplt->contents + iplt_index * RELA_ENTRY_SIZE;
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
elf_s390_finish_dynamic_symbol (bfd *output_bfd,
				struct bfd_link_info *info,
				struct elf_link_hash_entry *h,
				Elf_Internal_Sym *sym)
{
  struct elf_s390_link_hash_table *htab;
  struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry*)h;

  htab = elf_s390_hash_table (info);
  if (!htab)
    return false;

  if (h->plt.offset != (bfd_vma) -1)
    {
      if (!finish_plt_entry(output_bfd, info, h, htab, eh, sym))
        return false;
    }

  if (h->got.offset != (bfd_vma) -1
      && elf_s390_hash_entry(h)->tls_type != GOT_TLS_GD
      && elf_s390_hash_entry(h)->tls_type != GOT_TLS_IE
      && elf_s390_hash_entry(h)->tls_type != GOT_TLS_IE_NLT)
    {
      if (!finish_got_entry(output_bfd, info, h, htab))
        return false;
    }

  if (h->needs_copy)
    {
      if (!finish_copy_reloc(output_bfd, h, htab))
        return false;
    }

  if (h == htab->elf.hdynamic
      || h == htab->elf.hgot
      || h == htab->elf.hplt)
    sym->st_shndx = SHN_ABS;

  return true;
}

static bool
finish_plt_entry(bfd *output_bfd, struct bfd_link_info *info,
                struct elf_link_hash_entry *h,
                struct elf_s390_link_hash_table *htab,
                struct elf_s390_link_hash_entry *eh,
                Elf_Internal_Sym *sym)
{
  if (s390_is_ifunc_symbol_p (h) && h->def_regular)
    {
      elf_s390_finish_ifunc_symbol (output_bfd, info, h,
        htab, h->plt.offset,
        eh->ifunc_resolver_address +
        eh->ifunc_resolver_section->output_offset +
        eh->ifunc_resolver_section->output_section->vma);
    }
  else
    {
      if (!finish_regular_plt_entry(output_bfd, info, h, htab, sym))
        return false;
    }
  return true;
}

static bool
finish_regular_plt_entry(bfd *output_bfd, struct bfd_link_info *info,
                        struct elf_link_hash_entry *h,
                        struct elf_s390_link_hash_table *htab,
                        Elf_Internal_Sym *sym)
{
  if (h->dynindx == -1 || !htab->elf.splt || !htab->elf.sgotplt || !htab->elf.srelplt)
    return false;

  bfd_vma plt_index = (h->plt.offset - PLT_FIRST_ENTRY_SIZE) / PLT_ENTRY_SIZE;
  bfd_vma got_offset = (plt_index + 3) * GOT_ENTRY_SIZE;
  bfd_vma relative_offset = calculate_relative_offset(plt_index);

  if (!fill_plt_contents(output_bfd, info, h, htab, got_offset, relative_offset))
    return false;

  bfd_put_32 (output_bfd, plt_index * sizeof (Elf32_External_Rela),
              htab->elf.splt->contents + h->plt.offset + 28);

  bfd_put_32 (output_bfd,
              (htab->elf.splt->output_section->vma
               + htab->elf.splt->output_offset
               + h->plt.offset
               + 12),
              htab->elf.sgotplt->contents + got_offset);

  if (!create_plt_relocation(output_bfd, h, htab, plt_index, got_offset))
    return false;

  if (!h->def_regular)
    sym->st_shndx = SHN_UNDEF;

  return true;
}

static bfd_vma
calculate_relative_offset(bfd_vma plt_index)
{
  bfd_vma relative_offset = -((PLT_FIRST_ENTRY_SIZE + (PLT_ENTRY_SIZE * plt_index) + 18) / 2);
  if (-32768 > (int) relative_offset)
    relative_offset = -(unsigned) (((65536 / PLT_ENTRY_SIZE - 1) * PLT_ENTRY_SIZE) / 2);
  return relative_offset;
}

static bool
fill_plt_contents(bfd *output_bfd, struct bfd_link_info *info,
                 struct elf_link_hash_entry *h,
                 struct elf_s390_link_hash_table *htab,
                 bfd_vma got_offset, bfd_vma relative_offset)
{
  if (!bfd_link_pic(info))
    {
      memcpy (htab->elf.splt->contents + h->plt.offset, elf_s390_plt_entry, PLT_ENTRY_SIZE);
      bfd_put_32 (output_bfd, (bfd_vma) 0+(relative_offset << 16),
                  htab->elf.splt->contents + h->plt.offset + 20);
      bfd_put_32 (output_bfd,
                  (htab->elf.sgotplt->output_section->vma
                   + htab->elf.sgotplt->output_offset
                   + got_offset),
                  htab->elf.splt->contents + h->plt.offset + 24);
    }
  else if (got_offset < 4096)
    {
      memcpy (htab->elf.splt->contents + h->plt.offset, elf_s390_plt_pic12_entry, PLT_ENTRY_SIZE);
      bfd_put_16 (output_bfd, (bfd_vma)0xc000 | got_offset,
                  htab->elf.splt->contents + h->plt.offset + 2);
      bfd_put_32 (output_bfd, (bfd_vma) 0+(relative_offset << 16),
                  htab->elf.splt->contents + h->plt.offset + 20);
    }
  else if (got_offset < 32768)
    {
      memcpy (htab->elf.splt->contents + h->plt.offset, elf_s390_plt_pic16_entry, PLT_ENTRY_SIZE);
      bfd_put_16 (output_bfd, (bfd_vma)got_offset,
                  htab->elf.splt->contents + h->plt.offset + 2);
      bfd_put_32 (output_bfd, (bfd_vma) 0+(relative_offset << 16),
                  htab->elf.splt->contents + h->plt.offset + 20);
    }
  else
    {
      memcpy (htab->elf.splt->contents + h->plt.offset, elf_s390_plt_pic_entry, PLT_ENTRY_SIZE);
      bfd_put_32 (output_bfd, (bfd_vma) 0+(relative_offset << 16),
                  htab->elf.splt->contents + h->plt.offset + 20);
      bfd_put_32 (output_bfd, got_offset,
                  htab->elf.splt->contents + h->plt.offset + 24);
    }
  return true;
}

static bool
create_plt_relocation(bfd *output_bfd, struct elf_link_hash_entry *h,
                     struct elf_s390_link_hash_table *htab,
                     bfd_vma plt_index, bfd_vma got_offset)
{
  Elf_Internal_Rela rela;
  bfd_byte *loc;

  rela.r_offset = (htab->elf.sgotplt->output_section->vma
                   + htab->elf.sgotplt->output_offset
                   + got_offset);
  rela.r_info = ELF32_R_INFO (h->dynindx, R_390_JMP_SLOT);
  rela.r_addend = 0;
  loc = htab->elf.srelplt->contents + plt_index * sizeof (Elf32_External_Rela);
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
  return true;
}

static bool
finish_got_entry(bfd *output_bfd, struct bfd_link_info *info,
                struct elf_link_hash_entry *h,
                struct elf_s390_link_hash_table *htab)
{
  if (!htab->elf.sgot || !htab->elf.srelgot)
    return false;

  Elf_Internal_Rela rela;
  bfd_byte *loc;

  rela.r_offset = (htab->elf.sgot->output_section->vma
                   + htab->elf.sgot->output_offset
                   + (h->got.offset &~ (bfd_vma) 1));

  if (h->def_regular && s390_is_ifunc_symbol_p (h))
    {
      if (bfd_link_pic (info))
        {
          goto do_glob_dat;
        }
      else
        {
          bfd_put_32 (output_bfd, (htab->elf.iplt->output_section->vma
                                   + htab->elf.iplt->output_offset
                                   + h->plt.offset),
                      htab->elf.sgot->contents + h->got.offset);
          return true;
        }
    }
  else if (SYMBOL_REFERENCES_LOCAL (info, h))
    {
      if (UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
        return true;

      if (!(h->def_regular || ELF_COMMON_DEF_P (h)))
        return false;
        
      if ((h->got.offset & 1) == 0)
        return false;
        
      rela.r_info = ELF32_R_INFO (0, R_390_RELATIVE);
      rela.r_addend = (h->root.u.def.value
                       + h->root.u.def.section->output_section->vma
                       + h->root.u.def.section->output_offset);
    }
  else
    {
      if ((h->got.offset & 1) != 0)
        return false;
        
    do_glob_dat:
      bfd_put_32 (output_bfd, (bfd_vma) 0, htab->elf.sgot->contents + h->got.offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_390_GLOB_DAT);
      rela.r_addend = 0;
    }

  loc = htab->elf.srelgot->contents;
  loc += htab->elf.srelgot->reloc_count++ * sizeof (Elf32_External_Rela);
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
  return true;
}

static bool
finish_copy_reloc(bfd *output_bfd, struct elf_link_hash_entry *h,
                 struct elf_s390_link_hash_table *htab)
{
  if (h->dynindx == -1
      || (h->root.type != bfd_link_hash_defined
          && h->root.type != bfd_link_hash_defweak)
      || (!htab->elf.srelbss && !htab->elf.sreldynrelro))
    return false;

  Elf_Internal_Rela rela;
  asection *s;
  bfd_byte *loc;

  rela.r_offset = (h->root.u.def.value
                   + h->root.u.def.section->output_section->vma
                   + h->root.u.def.section->output_offset);
  rela.r_info = ELF32_R_INFO (h->dynindx, R_390_COPY);
  rela.r_addend = 0;
  
  if (h->root.u.def.section == htab->elf.sdynrelro)
    s = htab->elf.sreldynrelro;
  else
    s = htab->elf.srelbss;
    
  if (!s)
    return false;
    
  loc = s->contents + s->reloc_count++ * sizeof (Elf32_External_Rela);
  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
  return true;
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

static enum elf_reloc_type_class
elf_s390_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
			   const asection *rel_sec ATTRIBUTE_UNUSED,
			   const Elf_Internal_Rela *rela)
{
  bfd *abfd;
  const struct elf_backend_data *bed;
  struct elf_s390_link_hash_table *htab;
  unsigned long r_symndx;
  Elf_Internal_Sym sym;

  if (!info || !rela)
    return reloc_class_normal;

  abfd = info->output_bfd;
  if (!abfd)
    return reloc_class_normal;

  bed = get_elf_backend_data (abfd);
  if (!bed)
    return reloc_class_normal;

  htab = elf_s390_hash_table (info);
  if (!htab)
    return reloc_class_normal;

  r_symndx = ELF32_R_SYM (rela->r_info);

  if (!htab->elf.dynsym || !htab->elf.dynsym->contents)
    return reloc_class_normal;

  if (!bed->s->swap_symbol_in (abfd,
			       (htab->elf.dynsym->contents
				+ r_symndx * bed->s->sizeof_sym),
			       0, &sym))
    return reloc_class_normal;

  if (ELF_ST_TYPE (sym.st_info) == STT_GNU_IFUNC)
    return reloc_class_ifunc;

  switch (ELF32_R_TYPE (rela->r_info))
    {
    case R_390_RELATIVE:
      return reloc_class_relative;
    case R_390_JMP_SLOT:
      return reloc_class_plt;
    case R_390_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Finish up the dynamic sections.  */

static bool
elf_s390_finish_dynamic_sections (bfd *output_bfd,
				  struct bfd_link_info *info)
{
  struct elf_s390_link_hash_table *htab;
  bfd *dynobj;
  asection *sdyn;

  htab = elf_s390_hash_table (info);
  if (!htab)
    return false;

  dynobj = htab->elf.dynobj;
  if (!dynobj)
    return false;

  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (htab->elf.dynamic_sections_created)
    {
      if (!sdyn || !htab->elf.sgot)
        return false;

      if (!process_dynamic_entries(dynobj, output_bfd, sdyn, htab))
        return false;

      if (!setup_plt_first_entry(output_bfd, info, htab))
        return false;
    }

  if (!setup_got_entries(output_bfd, sdyn, htab))
    return false;

  return finish_local_ifunc_symbols(output_bfd, info, htab);
}

static bool
process_dynamic_entries(bfd *dynobj, bfd *output_bfd, asection *sdyn,
                       struct elf_s390_link_hash_table *htab)
{
  Elf32_External_Dyn *dyncon, *dynconend;

  dyncon = (Elf32_External_Dyn *) sdyn->contents;
  dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);

  for (; dyncon < dynconend; dyncon++)
    {
      Elf_Internal_Dyn dyn;
      asection *s;

      bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

      switch (dyn.d_tag)
        {
        case DT_PLTGOT:
          s = htab->elf.sgotplt;
          if (s)
            dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
          break;

        case DT_JMPREL:
          s = htab->elf.srelplt;
          if (s)
            dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
          break;

        case DT_PLTRELSZ:
          if (htab->elf.srelplt)
            {
              dyn.d_un.d_val = htab->elf.srelplt->size;
              if (htab->elf.irelplt)
                dyn.d_un.d_val += htab->elf.irelplt->size;
            }
          break;

        default:
          continue;
        }

      bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
    }

  return true;
}

static bool
setup_plt_first_entry(bfd *output_bfd, struct bfd_link_info *info,
                      struct elf_s390_link_hash_table *htab)
{
  if (!htab->elf.splt || htab->elf.splt->size <= 0)
    return true;

  memset (htab->elf.splt->contents, 0, PLT_FIRST_ENTRY_SIZE);

  if (bfd_link_pic (info))
    {
      memcpy (htab->elf.splt->contents, elf_s390_plt_pic_first_entry,
              PLT_FIRST_ENTRY_SIZE);
    }
  else
    {
      memcpy (htab->elf.splt->contents, elf_s390_plt_first_entry,
              PLT_FIRST_ENTRY_SIZE);
      if (htab->elf.sgotplt)
        {
          bfd_put_32 (output_bfd,
                      htab->elf.sgotplt->output_section->vma
                      + htab->elf.sgotplt->output_offset,
                      htab->elf.splt->contents + 24);
        }
    }

  elf_section_data (htab->elf.splt->output_section)->this_hdr.sh_entsize = 4;
  return true;
}

static bool
setup_got_entries(bfd *output_bfd, asection *sdyn,
                 struct elf_s390_link_hash_table *htab)
{
  if (!htab->elf.sgotplt)
    return true;

  if (htab->elf.sgotplt->size > 0)
    {
      bfd_vma dynamic_addr = 0;
      if (sdyn)
        dynamic_addr = sdyn->output_section->vma + sdyn->output_offset;

      bfd_put_32 (output_bfd, dynamic_addr, htab->elf.sgotplt->contents);
      bfd_put_32 (output_bfd, (bfd_vma) 0, htab->elf.sgotplt->contents + 4);
      bfd_put_32 (output_bfd, (bfd_vma) 0, htab->elf.sgotplt->contents + 8);
    }

  elf_section_data (htab->elf.sgotplt->output_section)->this_hdr.sh_entsize = 4;
  return true;
}

static bool
finish_local_ifunc_symbols(bfd *output_bfd, struct bfd_link_info *info,
                          struct elf_s390_link_hash_table *htab)
{
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      struct plt_entry *local_plt;
      Elf_Internal_Shdr *symtab_hdr;
      unsigned int i;

      if (!is_s390_elf (ibfd))
        continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      local_plt = elf_s390_local_plt (ibfd);

      if (!local_plt)
        continue;

      for (i = 0; i < symtab_hdr->sh_info; i++)
        {
          if (local_plt[i].plt.offset == (bfd_vma) -1)
            continue;

          Elf_Internal_Sym *isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, ibfd, i);
          if (!isym)
            return false;

          if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
            {
              asection *sec = local_plt[i].sec;
              if (sec)
                {
                  elf_s390_finish_ifunc_symbol (output_bfd, info, NULL, htab,
                                                local_plt[i].plt.offset,
                                                isym->st_value
                                                + sec->output_section->vma
                                                + sec->output_offset);
                }
            }
        }
    }

  return true;
}

/* Support for core dump NOTE sections.  */

static bool
elf_s390_grok_prstatus (bfd * abfd, Elf_Internal_Note * note)
{
  int offset;
  unsigned int size;

  if (!abfd || !note || !note->descdata)
    return false;

  if (note->descsz != 224)
    return false;

  if (!elf_tdata (abfd) || !elf_tdata (abfd)->core)
    return false;

  elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + 12);
  elf_tdata (abfd)->core->lwpid = bfd_get_32 (abfd, note->descdata + 24);

  offset = 72;
  size = 144;

  return _bfd_elfcore_make_pseudosection (abfd, ".reg",
					  size, note->descpos + offset);
}

static bool
elf_s390_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  if (!abfd || !note || !note->descdata)
    return false;

  if (note->descsz != 124)
    return false;

  if (!elf_tdata(abfd) || !elf_tdata(abfd)->core)
    return false;

  elf_tdata(abfd)->core->pid = bfd_get_32(abfd, note->descdata + 12);
  elf_tdata(abfd)->core->program = _bfd_elfcore_strndup(abfd, note->descdata + 28, 16);
  elf_tdata(abfd)->core->command = _bfd_elfcore_strndup(abfd, note->descdata + 44, 80);

  if (!elf_tdata(abfd)->core->command)
    return false;

  char *command = elf_tdata(abfd)->core->command;
  int n = strlen(command);

  if (n > 0 && command[n - 1] == ' ')
    command[n - 1] = '\0';

  return true;
}

static char *
elf_s390_write_core_note (bfd *abfd, char *buf, int *bufsiz,
			  int note_type, ...)
{
  va_list ap;

  switch (note_type)
    {
    case NT_PRPSINFO:
      {
	char data[124] ATTRIBUTE_NONSTRING = { 0 };
	const char *fname, *psargs;

	va_start (ap, note_type);
	fname = va_arg (ap, const char *);
	psargs = va_arg (ap, const char *);
	va_end (ap);

	if (fname != NULL)
	  {
	    strncpy (data + 28, fname, 15);
	    data[28 + 15] = '\0';
	  }
	if (psargs != NULL)
	  {
	    strncpy (data + 44, psargs, 79);
	    data[44 + 79] = '\0';
	  }
	return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				   &data, sizeof (data));
      }

    case NT_PRSTATUS:
      {
	char data[224] = { 0 };
	long pid;
	int cursig;
	const void *gregs;

	va_start (ap, note_type);
	pid = va_arg (ap, long);
	cursig = va_arg (ap, int);
	gregs = va_arg (ap, const void *);
	va_end (ap);

	bfd_put_16 (abfd, cursig, data + 12);
	bfd_put_32 (abfd, pid, data + 24);
	if (gregs != NULL)
	  memcpy (data + 72, gregs, 144);
	return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				   &data, sizeof (data));
      }

    default:
      return NULL;
    }
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
elf_s390_plt_sym_val (bfd_vma i, const asection *plt,
		      const arelent *rel ATTRIBUTE_UNUSED)
{
  if (!plt)
    return 0;
  
  return plt->vma + PLT_FIRST_ENTRY_SIZE + i * PLT_ENTRY_SIZE;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
elf32_s390_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd;

  if (!info)
    return false;

  obfd = info->output_bfd;

  if (!ibfd || !obfd)
    return false;

  if (!is_s390_elf (ibfd) || !is_s390_elf (obfd))
    return true;

  if (!elf_s390_merge_obj_attributes (ibfd, info))
    return false;

  elf_elfheader (obfd)->e_flags |= elf_elfheader (ibfd)->e_flags;
  return true;
}


#define TARGET_BIG_SYM	s390_elf32_vec
#define TARGET_BIG_NAME	"elf32-s390"
#define ELF_ARCH	bfd_arch_s390
#define ELF_TARGET_ID	S390_ELF_DATA
#define ELF_MACHINE_CODE EM_S390
#define ELF_MACHINE_ALT1 EM_S390_OLD
#define ELF_MAXPAGESIZE 0x1000

#define elf_backend_can_gc_sections	1
#define elf_backend_can_refcount	1
#define elf_backend_want_got_plt	1
#define elf_backend_plt_readonly	1
#define elf_backend_want_plt_sym	0
#define elf_backend_got_header_size	12
#define elf_backend_want_dynrelro	1
#define elf_backend_rela_normal		1

#define elf_info_to_howto		      elf_s390_info_to_howto

#define bfd_elf32_bfd_is_local_label_name     elf_s390_is_local_label_name
#define bfd_elf32_bfd_link_hash_table_create  elf_s390_link_hash_table_create
#define bfd_elf32_bfd_reloc_type_lookup	      elf_s390_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup elf_s390_reloc_name_lookup

#define bfd_elf32_bfd_merge_private_bfd_data  elf32_s390_merge_private_bfd_data

#define elf_backend_adjust_dynamic_symbol     elf_s390_adjust_dynamic_symbol
#define elf_backend_check_relocs	      elf_s390_check_relocs
#define elf_backend_copy_indirect_symbol      elf_s390_copy_indirect_symbol
#define elf_backend_create_dynamic_sections   _bfd_elf_create_dynamic_sections
#define elf_backend_finish_dynamic_sections   elf_s390_finish_dynamic_sections
#define elf_backend_finish_dynamic_symbol     elf_s390_finish_dynamic_symbol
#define elf_backend_gc_mark_hook	      elf_s390_gc_mark_hook
#define elf_backend_reloc_type_class	      elf_s390_reloc_type_class
#define elf_backend_relocate_section	      elf_s390_relocate_section
#define elf_backend_late_size_sections	      elf_s390_late_size_sections
#define elf_backend_init_index_section	      _bfd_elf_init_1_index_section
#define elf_backend_grok_prstatus	      elf_s390_grok_prstatus
#define elf_backend_grok_psinfo		      elf_s390_grok_psinfo
#define elf_backend_write_core_note	      elf_s390_write_core_note
#define elf_backend_plt_sym_val		      elf_s390_plt_sym_val
#define elf_backend_sort_relocs_p	      elf_s390_elf_sort_relocs_p

#define bfd_elf32_mkobject		elf_s390_mkobject
#define elf_backend_object_p		elf_s390_object_p

#define elf_backend_linux_prpsinfo32_ugid16	true

#include "elf32-target.h"
