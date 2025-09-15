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

typedef struct {
    bfd_reloc_code_real_type code;
    reloc_howto_type *howto_ptr;
} reloc_lookup_entry;

static const reloc_lookup_entry s390_reloc_mappings[] = {
    { BFD_RELOC_NONE, &elf_howto_table[R_390_NONE] },
    { BFD_RELOC_8, &elf_howto_table[R_390_8] },
    { BFD_RELOC_390_12, &elf_howto_table[R_390_12] },
    { BFD_RELOC_16, &elf_howto_table[R_390_16] },
    { BFD_RELOC_32, &elf_howto_table[R_390_32] },
    { BFD_RELOC_CTOR, &elf_howto_table[R_390_32] },
    { BFD_RELOC_32_PCREL, &elf_howto_table[R_390_PC32] },
    { BFD_RELOC_390_GOT12, &elf_howto_table[R_390_GOT12] },
    { BFD_RELOC_32_GOT_PCREL, &elf_howto_table[R_390_GOT32] },
    { BFD_RELOC_390_PLT32, &elf_howto_table[R_390_PLT32] },
    { BFD_RELOC_390_COPY, &elf_howto_table[R_390_COPY] },
    { BFD_RELOC_390_GLOB_DAT, &elf_howto_table[R_390_GLOB_DAT] },
    { BFD_RELOC_390_JMP_SLOT, &elf_howto_table[R_390_JMP_SLOT] },
    { BFD_RELOC_390_RELATIVE, &elf_howto_table[R_390_RELATIVE] },
    { BFD_RELOC_32_GOTOFF, &elf_howto_table[R_390_GOTOFF32] },
    { BFD_RELOC_390_GOTPC, &elf_howto_table[R_390_GOTPC] },
    { BFD_RELOC_390_GOT16, &elf_howto_table[R_390_GOT16] },
    { BFD_RELOC_16_PCREL, &elf_howto_table[R_390_PC16] },
    { BFD_RELOC_390_PC12DBL, &elf_howto_table[R_390_PC12DBL] },
    { BFD_RELOC_390_PLT12DBL, &elf_howto_table[R_390_PLT12DBL] },
    { BFD_RELOC_390_PC16DBL, &elf_howto_table[R_390_PC16DBL] },
    { BFD_RELOC_390_PLT16DBL, &elf_howto_table[R_390_PLT16DBL] },
    { BFD_RELOC_390_PC24DBL, &elf_howto_table[R_390_PC24DBL] },
    { BFD_RELOC_390_PLT24DBL, &elf_howto_table[R_390_PLT24DBL] },
    { BFD_RELOC_390_PC32DBL, &elf_howto_table[R_390_PC32DBL] },
    { BFD_RELOC_390_PLT32DBL, &elf_howto_table[R_390_PLT32DBL] },
    { BFD_RELOC_390_GOTPCDBL, &elf_howto_table[R_390_GOTPCDBL] },
    { BFD_RELOC_390_GOTENT, &elf_howto_table[R_390_GOTENT] },
    { BFD_RELOC_16_GOTOFF, &elf_howto_table[R_390_GOTOFF16] },
    { BFD_RELOC_390_GOTPLT12, &elf_howto_table[R_390_GOTPLT12] },
    { BFD_RELOC_390_GOTPLT16, &elf_howto_table[R_390_GOTPLT16] },
    { BFD_RELOC_390_GOTPLT32, &elf_howto_table[R_390_GOTPLT32] },
    { BFD_RELOC_390_GOTPLTENT, &elf_howto_table[R_390_GOTPLTENT] },
    { BFD_RELOC_390_PLTOFF16, &elf_howto_table[R_390_PLTOFF16] },
    { BFD_RELOC_390_PLTOFF32, &elf_howto_table[R_390_PLTOFF32] },
    { BFD_RELOC_390_TLS_LOAD, &elf_howto_table[R_390_TLS_LOAD] },
    { BFD_RELOC_390_TLS_GDCALL, &elf_howto_table[R_390_TLS_GDCALL] },
    { BFD_RELOC_390_TLS_LDCALL, &elf_howto_table[R_390_TLS_LDCALL] },
    { BFD_RELOC_390_TLS_GD32, &elf_howto_table[R_390_TLS_GD32] },
    { BFD_RELOC_390_TLS_GOTIE12, &elf_howto_table[R_390_TLS_GOTIE12] },
    { BFD_RELOC_390_TLS_GOTIE32, &elf_howto_table[R_390_TLS_GOTIE32] },
    { BFD_RELOC_390_TLS_LDM32, &elf_howto_table[R_390_TLS_LDM32] },
    { BFD_RELOC_390_TLS_IE32, &elf_howto_table[R_390_TLS_IE32] },
    { BFD_RELOC_390_TLS_IEENT, &elf_howto_table[R_390_TLS_IEENT] },
    { BFD_RELOC_390_TLS_LE32, &elf_howto_table[R_390_TLS_LE32] },
    { BFD_RELOC_390_TLS_LDO32, &elf_howto_table[R_390_TLS_LDO32] },
    { BFD_RELOC_390_TLS_DTPMOD, &elf_howto_table[R_390_TLS_DTPMOD] },
    { BFD_RELOC_390_TLS_DTPOFF, &elf_howto_table[R_390_TLS_DTPOFF] },
    { BFD_RELOC_390_TLS_TPOFF, &elf_howto_table[R_390_TLS_TPOFF] },
    { BFD_RELOC_390_20, &elf_howto_table[R_390_20] },
    { BFD_RELOC_390_GOT20, &elf_howto_table[R_390_GOT20] },
    { BFD_RELOC_390_GOTPLT20, &elf_howto_table[R_390_GOTPLT20] },
    { BFD_RELOC_390_TLS_GOTIE20, &elf_howto_table[R_390_TLS_GOTIE20] },
    { BFD_RELOC_390_IRELATIVE, &elf_howto_table[R_390_IRELATIVE] },
    { BFD_RELOC_VTABLE_INHERIT, &elf32_s390_vtinherit_howto },
    { BFD_RELOC_VTABLE_ENTRY, &elf32_s390_vtentry_howto }
};

static reloc_howto_type *
elf_s390_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    bfd_reloc_code_real_type code)
{
    for (size_t i = 0; i < sizeof(s390_reloc_mappings) / sizeof(s390_reloc_mappings[0]); ++i) {
        if (s390_reloc_mappings[i].code == code) {
            return s390_reloc_mappings[i].howto_ptr;
        }
    }
    return NULL;
}

static reloc_howto_type *
elf_s390_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    const char *r_name)
{
  size_t i;
  const size_t num_elf_table_entries = sizeof(elf_howto_table) / sizeof(elf_howto_table[0]);

  for (i = 0; i < num_elf_table_entries; ++i)
    if (elf_howto_table[i].name != NULL && strcasecmp(elf_howto_table[i].name, r_name) == 0)
      return &elf_howto_table[i];

  static reloc_howto_type * const specific_howtos[] = {
    &elf32_s390_vtinherit_howto,
    &elf32_s390_vtentry_howto
  };
  const size_t num_specific_howtos = sizeof(specific_howtos) / sizeof(specific_howtos[0]);

  for (i = 0; i < num_specific_howtos; ++i)
    if (strcasecmp(specific_howtos[i]->name, r_name) == 0)
      return specific_howtos[i];

  return NULL;
}

/* We need to use ELF32_R_TYPE so we have our own copy of this function,
   and elf32-s390.c has its own copy.  */

static bool
elf_s390_info_to_howto (bfd *abfd,
			arelent *cache_ptr,
			Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE(dst->r_info);
  const struct bfd_reloc_howto_type *howto_to_assign = NULL;

  switch (r_type)
    {
    case R_390_GNU_VTINHERIT:
      howto_to_assign = &elf32_s390_vtinherit_howto;
      break;

    case R_390_GNU_VTENTRY:
      howto_to_assign = &elf32_s390_vtentry_howto;
      break;

    default:
      if (r_type >= sizeof (elf_howto_table) / sizeof (elf_howto_table[0]))
	{
	  _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			      abfd, r_type);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      howto_to_assign = &elf_howto_table[r_type];
      break;
    }

  cache_ptr->howto = howto_to_assign;
  return true;
}

/* A relocation function which doesn't do anything.  */
static bfd_reloc_status_type
s390_tls_reloc (bfd *abfd ATTRIBUTE_UNUSED,
		arelent *reloc_entry,
		asymbol *symbol ATTRIBUTE_UNUSED,
		void * data ATTRIBUTE_UNUSED,
		const asection *input_section,
		bfd *output_bfd,
		char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd)
    reloc_entry->address += input_section->output_offset;
  return bfd_reloc_ok;
}

/* Handle the large displacement relocs.  */
static bfd_reloc_status_type
s390_elf_ldisp_reloc (bfd *abfd,
                      arelent *reloc_entry,
                      asymbol *symbol,
                      void *data,
                      asection *input_section,
                      bfd *output_bfd,
                      char **error_message ATTRIBUTE_UNUSED)
{
  reloc_howto_type *howto = reloc_entry->howto;
  bfd_vma relocation_value;
  bfd_vma insn_value;

  /* Constants for improved readability and maintainability */
#define S390_LDISP_LOW_BITS_MASK         0xfffU
#define S390_LDISP_HIGH_BITS_MASK        0xff000U
#define S390_LDISP_HIGH_BITS_SHIFT_LEFT  16
#define S390_LDISP_HIGH_BITS_SHIFT_RIGHT 4

#define S390_LDISP_RELOC_MIN             ((bfd_signed_vma) -0x80000)
#define S390_LDISP_RELOC_MAX             ((bfd_signed_vma)  0x7ffff)

  /* Phase 1: Handle cases when output_bfd is present.
   * If output_bfd is not NULL, the function always returns early.
   */
  if (output_bfd != NULL)
    {
      bool is_section_symbol = (symbol->flags & BSF_SECTION_SYM) != 0;
      bool is_partial_inplace = howto->partial_inplace;
      bool is_addend_zero = reloc_entry->addend == 0;

      /* First condition from the original code for output_bfd processing. */
      if (!is_section_symbol && (!is_partial_inplace || is_addend_zero))
        {
          reloc_entry->address += input_section->output_offset;
          return bfd_reloc_ok;
        }
      else
        {
          /* If output_bfd is present but the specific conditions above are not met,
           * then the original code returns bfd_reloc_continue.
           */
          return bfd_reloc_continue;
        }
    }

  /* Phase 2: Main relocation logic (only executed if output_bfd is NULL). */

  /* Check if the relocation address is out of section bounds. */
  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    {
      return bfd_reloc_outofrange;
    }

  /* Calculate the target relocation value. */
  relocation_value = (symbol->value
                      + symbol->section->output_section->vma
                      + symbol->section->output_offset);
  relocation_value += reloc_entry->addend;

  /* Adjust for PC-relative relocation if required. */
  if (howto->pc_relative)
    {
      relocation_value -= (input_section->output_section->vma
                           + input_section->output_offset);
      relocation_value -= reloc_entry->address;
    }

  /* Read the instruction, apply the relocation, and write it back. */
  bfd_byte *insn_addr = (bfd_byte *) data + reloc_entry->address;
  insn_value = bfd_get_32 (abfd, insn_addr);

  /* Apply LDISP specific bit manipulation using defined constants. */
  insn_value |= ((relocation_value & S390_LDISP_LOW_BITS_MASK) << S390_LDISP_HIGH_BITS_SHIFT_LEFT)
             |   ((relocation_value & S390_LDISP_HIGH_BITS_MASK) >> S390_LDISP_HIGH_BITS_SHIFT_RIGHT);

  bfd_put_32 (abfd, insn_value, insn_addr);

  /* Check for relocation overflow using defined range limits. */
  if ((bfd_signed_vma) relocation_value < S390_LDISP_RELOC_MIN
      || (bfd_signed_vma) relocation_value > S390_LDISP_RELOC_MAX)
    {
      return bfd_reloc_overflow;
    }
  else
    {
      return bfd_reloc_ok;
    }

#undef S390_LDISP_LOW_BITS_MASK
#undef S390_LDISP_HIGH_BITS_MASK
#undef S390_LDISP_HIGH_BITS_SHIFT_LEFT
#undef S390_LDISP_HIGH_BITS_SHIFT_RIGHT
#undef S390_LDISP_RELOC_MIN
#undef S390_LDISP_RELOC_MAX
}

static bool
elf_s390_is_local_label_name (bfd *abfd, const char *name)
{
  if (name == NULL)
    return false;

  if (name[0] == '.' && name[1] != '\0' && (name[1] == 'X' || name[1] == 'L'))
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
  bool allocated_successfully = bfd_elf_allocate_object (abfd, sizeof (struct elf_s390_obj_tdata));

  if (!allocated_successfully)
    {
      return false;
    }

  return true;
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
  struct elf_s390_link_hash_entry *eh_s390 = (struct elf_s390_link_hash_entry *) entry;

  if (eh_s390 == NULL)
    {
      eh_s390 = bfd_hash_allocate (table, sizeof (*eh_s390));
      if (eh_s390 == NULL)
        {
          return NULL;
        }
    }

  entry = _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) eh_s390, table, string);
  if (entry == NULL)
    {
      return NULL;
    }

  eh_s390 = (struct elf_s390_link_hash_entry *) entry;

  eh_s390->gotplt_refcount = 0;
  eh_s390->tls_type = GOT_UNKNOWN;
  eh_s390->ifunc_resolver_address = 0;
  eh_s390->ifunc_resolver_section = NULL;

  return entry;
}

/* Create an s390 ELF linker hash table.  */

static struct bfd_link_hash_table *
elf_s390_link_hash_table_create (bfd *abfd)
{
  struct elf_s390_link_hash_table *ret;

  ret = bfd_zmalloc (sizeof *ret);
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
  struct elf_s390_link_hash_entry *edir = (struct elf_s390_link_hash_entry *) dir;
  struct elf_s390_link_hash_entry *eind = (struct elf_s390_link_hash_entry *) ind;

  if (ind->root.type == bfd_link_hash_indirect
      && dir->got.refcount <= 0)
    {
      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
    }

  if (ELIMINATE_COPY_RELOCS
      && ind->root.type != bfd_link_hash_indirect
      && dir->dynamic_adjusted)
    {
      if (dir->versioned != versioned_hidden)
	dir->ref_dynamic |= ind->ref_dynamic;
      dir->ref_regular |= ind->ref_regular;
      dir->ref_regular_nonweak |= ind->ref_regular_nonweak;
      dir->needs_plt |= ind->needs_plt;
    }
  else
    _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

static int
elf_s390_tls_transition (struct bfd_link_info *info,
			 int r_type,
			 int is_local)
{
  if (bfd_link_pic (info))
    {
      return r_type;
    }

  /* R_390_TLS_LDM32 always transitions to R_390_TLS_LE32 when not PIC,
   * regardless of 'is_local'. Handle this case first for clarity. */
  if (r_type == R_390_TLS_LDM32)
    {
      return R_390_TLS_LE32;
    }

  if (is_local)
    {
      switch (r_type)
        {
        case R_390_TLS_GD32:
        case R_390_TLS_IE32:
        case R_390_TLS_GOTIE32:
          return R_390_TLS_LE32;
        default:
          return r_type;
        }
    }
  else /* !is_local */
    {
      switch (r_type)
        {
        case R_390_TLS_GD32:
        case R_390_TLS_IE32:
          return R_390_TLS_IE32;
        case R_390_TLS_GOTIE32:
          return R_390_TLS_GOTIE32;
        default:
          return r_type;
        }
    }
}

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static void
s390_ensure_dynobj_initialized(struct elf_s390_link_hash_table *htab, bfd *abfd)
{
  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;
}

static bool
s390_ensure_ifunc_sections(bfd *abfd, struct bfd_link_info *info,
                           struct elf_s390_link_hash_table *htab)
{
  s390_ensure_dynobj_initialized(htab, abfd);
  return s390_elf_create_ifunc_sections(htab->elf.dynobj, info);
}

static bool
s390_ensure_got_section(bfd *abfd, struct bfd_link_info *info,
                        struct elf_s390_link_hash_table *htab)
{
  s390_ensure_dynobj_initialized(htab, abfd);
  return _bfd_elf_create_got_section(htab->elf.dynobj, info);
}

static bool
s390_ensure_local_syminfo(bfd *abfd, Elf_Internal_Shdr *symtab_hdr,
                          bfd_signed_vma **local_got_refcounts_ptr)
{
  if (*local_got_refcounts_ptr == NULL)
    {
      if (!elf_s390_allocate_local_syminfo(abfd, symtab_hdr))
        return false;
      *local_got_refcounts_ptr = elf_local_got_refcounts(abfd);
    }
  return true;
}

static bool
s390_resolve_symbol_entry(bfd *abfd,
                          struct elf_s390_link_hash_table *htab,
                          Elf_Internal_Shdr *symtab_hdr,
                          struct elf_link_hash_entry **sym_hashes,
                          unsigned int r_symndx,
                          struct elf_link_hash_entry **h_out,
                          Elf_Internal_Sym **isym_out)
{
  if (r_symndx < symtab_hdr->sh_info)
    {
      *isym_out = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
      if (*isym_out == NULL)
        return false;
      *h_out = NULL;
    }
  else
    {
      struct elf_link_hash_entry *h_tmp = sym_hashes[r_symndx - symtab_hdr->sh_info];
      while (h_tmp->root.type == bfd_link_hash_indirect || h_tmp->root.type == bfd_link_hash_warning)
        h_tmp = (struct elf_link_hash_entry *) h_tmp->root.u.i.link;
      *h_out = h_tmp;
      *isym_out = NULL;
    }
  return true;
}

static bool
s390_handle_local_ifunc_reloc(bfd *abfd, struct bfd_link_info *info,
                               struct elf_s390_link_hash_table *htab,
                               Elf_Internal_Shdr *symtab_hdr,
                               bfd_signed_vma **local_got_refcounts_ptr,
                               unsigned int r_symndx, Elf_Internal_Sym *isym)
{
  if (ELF_ST_TYPE(isym->st_info) == STT_GNU_IFUNC)
    {
      if (!s390_ensure_ifunc_sections(abfd, info, htab))
        return false;
      if (!s390_ensure_local_syminfo(abfd, symtab_hdr, local_got_refcounts_ptr))
        return false;

      struct plt_entry *plt = elf_s390_local_plt(abfd);
      plt[r_symndx].plt.refcount++;
    }
  return true;
}

static bool
s390_update_tls_got_refcounts_and_type(bfd *abfd,
                                       struct bfd_link_info *info,
                                       struct elf_s390_link_hash_table *htab,
                                       unsigned int r_symndx,
                                       unsigned int r_type_trans,
                                       struct elf_link_hash_entry *h,
                                       bfd_signed_vma *local_got_refcounts)
{
  int tls_type = GOT_UNKNOWN;
  switch (r_type_trans)
    {
    case R_390_GOT12:
    case R_390_GOT16:
    case R_390_GOT20:
    case R_390_GOT32:
    case R_390_GOTENT:
      tls_type = GOT_NORMAL;
      break;
    case R_390_TLS_GD32:
      tls_type = GOT_TLS_GD;
      break;
    case R_390_TLS_IE32:
    case R_390_TLS_GOTIE32:
      tls_type = GOT_TLS_IE;
      break;
    case R_390_TLS_GOTIE12:
    case R_390_TLS_GOTIE20:
    case R_390_TLS_IEENT:
      tls_type = GOT_TLS_IE_NLT;
      break;
    default:
      /* This helper is only called for known TLS/GOT types. */
      return false;
    }

  int old_tls_type;
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
                             abfd, h ? h->root.root.string : "<local_sym>");
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
  return true;
}

static bool
s390_record_dynamic_relocation_copy(bfd *abfd,
                                     struct bfd_link_info *info,
                                     struct elf_s390_link_hash_table *htab,
                                     asection **sreloc_ptr,
                                     asection *sec,
                                     const Elf_Internal_Rela *rel,
                                     struct elf_link_hash_entry *h,
                                     unsigned int r_symndx,
                                     Elf_Internal_Shdr *symtab_hdr)
{
  bool needs_dynamic_copy = false;
  unsigned int r_type_val = ELF32_R_TYPE(rel->r_info);

  if (bfd_link_pic(info))
    {
      if ((sec->flags & SEC_ALLOC) != 0)
        {
          if (!(r_type_val == R_390_PC16
                || r_type_val == R_390_PC12DBL
                || r_type_val == R_390_PC16DBL
                || r_type_val == R_390_PC24DBL
                || r_type_val == R_390_PC32DBL
                || r_type_val == R_390_PC32))
            needs_dynamic_copy = true;
          else if (h != NULL
                   && (!SYMBOLIC_BIND(info, h)
                       || h->root.type == bfd_link_hash_defweak
                       || !h->def_regular))
            needs_dynamic_copy = true;
        }
    }
  else if (ELIMINATE_COPY_RELOCS
           && (sec->flags & SEC_ALLOC) != 0
           && h != NULL
           && (h->root.type == bfd_link_hash_defweak
               || !h->def_regular))
    {
      needs_dynamic_copy = true;
    }

  if (needs_dynamic_copy)
    {
      struct elf_dyn_relocs *p;
      struct elf_dyn_relocs **head;

      if (*sreloc_ptr == NULL)
        {
          s390_ensure_dynobj_initialized(htab, abfd);
          *sreloc_ptr = _bfd_elf_make_dynamic_reloc_section
            (sec, htab->elf.dynobj, 2, abfd, /*rela?*/ true);
          if (*sreloc_ptr == NULL)
            return false;
        }

      if (h != NULL)
        {
          head = &h->dyn_relocs;
        }
      else
        {
          Elf_Internal_Sym *isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
          if (isym == NULL)
            return false;

          asection *s = bfd_section_from_elf_index(abfd, isym->st_shndx);
          if (s == NULL)
            s = sec;

          void *vpp = &elf_section_data(s)->local_dynrel;
          head = (struct elf_dyn_relocs **) vpp;
        }

      p = *head;
      if (p == NULL || p->sec != sec)
        {
          size_t amt = sizeof *p;
          p = ((struct elf_dyn_relocs *)
               bfd_alloc(htab->elf.dynobj, amt));
          if (p == NULL)
            return false;
          p->next = *head;
          *head = p;
          p->sec = sec;
          p->count = 0;
          p->pc_count = 0;
        }

      p->count += 1;
      if (r_type_val == R_390_PC16
          || r_type_val == R_390_PC12DBL
          || r_type_val == R_390_PC16DBL
          || r_type_val == R_390_PC24DBL
          || r_type_val == R_390_PC32DBL
          || r_type_val == R_390_PC32)
        p->pc_count += 1;
    }
  return true;
}

static bool
elf_s390_check_relocs (bfd *abfd,
		       struct bfd_link_info *info,
		       asection *sec,
		       const Elf_Internal_Rela *relocs)
{
  struct elf_s390_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_signed_vma *local_got_refcounts;
  asection *sreloc = NULL;

  if (bfd_link_relocatable (info))
    return true;

  BFD_ASSERT (is_s390_elf (abfd));

  htab = elf_s390_hash_table (info);
  symtab_hdr = &elf_symtab_hdr (abfd);
sym_hashes = elf_sym_hashes (abfd);
  local_got_refcounts = elf_local_got_refcounts (abfd);

  const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;
  for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; rel++)
    {
      unsigned int r_symndx = ELF32_R_SYM (rel->r_info);
      unsigned int r_type_orig = ELF32_R_TYPE (rel->r_info);
      unsigned int r_type_trans; /* r_type after TLS transition */

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  _bfd_error_handler (_("%pB: bad symbol index: %d"), abfd, r_symndx);
	  return false;
	}

      struct elf_link_hash_entry *h = NULL;
      Elf_Internal_Sym *isym = NULL;
      if (!s390_resolve_symbol_entry(abfd, htab, symtab_hdr, sym_hashes,
                                     r_symndx, &h, &isym))
        return false;

      if (isym != NULL) /* A local symbol */
        {
          if (!s390_handle_local_ifunc_reloc(abfd, info, htab, symtab_hdr,
                                            &local_got_refcounts, r_symndx, isym))
            return false;
        }

      r_type_trans = elf_s390_tls_transition(info, r_type_orig, h == NULL);

      /* First pass to ensure required sections and arrays are allocated. */
      switch (r_type_trans)
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
          if (h == NULL && local_got_refcounts == NULL)
            {
              if (!s390_ensure_local_syminfo(abfd, symtab_hdr, &local_got_refcounts))
                return false;
            }
          BFD_FALLTHROUGH;
        case R_390_GOTOFF16:
        case R_390_GOTOFF32:
        case R_390_GOTPC:
        case R_390_GOTPCDBL:
          if (htab->elf.sgot == NULL)
            {
              if (!s390_ensure_got_section(abfd, info, htab))
                return false;
            }
          break;
        default:
          break;
        }

      if (h != NULL) /* A global symbol */
        {
          if (s390_is_ifunc_symbol_p(h) && h->def_regular)
            {
              if (!s390_ensure_ifunc_sections(abfd, info, htab))
                return false;
              h->ref_regular = 1;
              h->needs_plt = 1;
            }
        }

      /* Second pass to process specific relocation requirements. */
      switch (r_type_trans)
        {
        case R_390_GOTPC:
        case R_390_GOTPCDBL:
          break;

        case R_390_GOTOFF16:
        case R_390_GOTOFF32:
          if (h == NULL || !s390_is_ifunc_symbol_p(h) || !h->def_regular)
            break;
          BFD_FALLTHROUGH;

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
              ((struct elf_s390_link_hash_entry *) h)->gotplt_refcount++;
              h->needs_plt = 1;
              h->plt.refcount += 1;
            }
          else
            local_got_refcounts[r_symndx] += 1;
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
          BFD_FALLTHROUGH;

        case R_390_GOT12:
        case R_390_GOT16:
        case R_390_GOT20:
        case R_390_GOT32:
        case R_390_GOTENT:
        case R_390_TLS_GD32:
          if (!s390_update_tls_got_refcounts_and_type(abfd, info, htab, r_symndx,
                                                      r_type_trans, h, local_got_refcounts))
            return false;

          /* Only R_390_TLS_IE32 continues here to the TLS_LE32 logic.
             Other R_390_GOT* and R_390_TLS_GD32 types break after updating TLS. */
          if (r_type_orig != R_390_TLS_IE32)
            break;
          BFD_FALLTHROUGH;

        case R_390_TLS_LE32:
          if (r_type_orig == R_390_TLS_LE32 && bfd_link_pie(info))
            break;

          if (!bfd_link_pic(info))
            break;
          info->flags |= DF_STATIC_TLS;
          BFD_FALLTHROUGH;

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
          if (!s390_record_dynamic_relocation_copy(abfd, info, htab, &sreloc, sec,
                                                   rel, h, r_symndx, symtab_hdr))
            return false;
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
  if (h != NULL
      && (ELF32_R_TYPE (rel->r_info) == R_390_GNU_VTINHERIT
	  || ELF32_R_TYPE (rel->r_info) == R_390_GNU_VTENTRY))
    {
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

  if (h == NULL)
    return;

  if (h->gotplt_refcount <= 0)
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
  if (s390_is_ifunc_symbol_p (h))
    {
      if (h->ref_regular && SYMBOL_CALLS_LOCAL (info, h))
	{
	  bfd_size_type pc_count = 0, total_reloc_count = 0;
	  struct elf_dyn_relocs **pp;
	  struct elf_dyn_relocs *p;

	  for (pp = &h->dyn_relocs; (p = *pp) != NULL; )
	    {
	      pc_count += p->pc_count;
	      p->count -= p->pc_count;
	      p->pc_count = 0;
	      total_reloc_count += p->count;
	      if (p->count == 0)
		*pp = p->next;
	      else
		pp = &p->next;
	    }

	  if (pc_count || total_reloc_count)
	    {
	      h->needs_plt = 1;
	      h->non_got_ref = 1;
	      if (h->plt.refcount < 1)
		h->plt.refcount = 1;
	      else
		h->plt.refcount++;
	    }
	}

      if (h->plt.refcount < 1)
	{
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}
      return true;
    }

  if (h->type == STT_FUNC
      || h->needs_plt)
    {
      if (h->plt.refcount < 1
	  || SYMBOL_CALLS_LOCAL (info, h)
	  || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	{
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	  elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *) h);
	}

      return true;
    }
  else
    {
      h->plt.offset = (bfd_vma) -1;
    }

  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      if (ELIMINATE_COPY_RELOCS || info->nocopyreloc)
	h->non_got_ref = def->non_got_ref;
      return true;
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

  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  asection *target_section;
  asection *reloc_section;

  if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      target_section = htab->elf.sdynrelro;
      reloc_section = htab->elf.sreldynrelro;
    }
  else
    {
      target_section = htab->elf.sdynbss;
      reloc_section = htab->elf.srelbss;
    }
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      reloc_section->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, target_section);
}

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static inline bool ensure_dynamic_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h)
{
  if (h->dynindx == -1 && !h->forced_local)
    {
      return bfd_elf_link_record_dynamic_symbol(info, h);
    }
  return true;
}

static bool
allocate_dynrelocs (struct elf_link_hash_entry *h, void * inf)
{
  struct bfd_link_info *info = (struct bfd_link_info *) inf;
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  struct elf_s390_link_hash_entry *s390_h = elf_s390_hash_entry(h);

  if (h->root.type == bfd_link_hash_indirect)
    return true;

  if (s390_is_ifunc_symbol_p (h) && h->def_regular)
    return s390_elf_allocate_ifunc_dyn_relocs (info, h);

  bool dynamic_sections_created = htab->elf.dynamic_sections_created;
  bool pic_mode = bfd_link_pic(info);
  bool needs_plt_allocation = false;

  if (dynamic_sections_created && h->plt.refcount > 0)
    {
      if (pic_mode || WILL_CALL_FINISH_DYNAMIC_SYMBOL(dynamic_sections_created, 0, h))
        {
          needs_plt_allocation = true;
        }
    }

  if (needs_plt_allocation)
    {
      if (!ensure_dynamic_symbol(info, h))
        return false;

      asection *s_plt = htab->elf.splt;

      if (s_plt->size == 0)
        s_plt->size += PLT_FIRST_ENTRY_SIZE;

      h->plt.offset = s_plt->size;

      if (!pic_mode && !h->def_regular)
        {
          h->root.u.def.section = s_plt;
          h->root.u.def.value = h->plt.offset;
        }

      s_plt->size += PLT_ENTRY_SIZE;
      htab->elf.sgotplt->size += GOT_ENTRY_SIZE;
      htab->elf.srelplt->size += sizeof (Elf32_External_Rela);
    }
  else
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
      elf_s390_adjust_gotplt(s390_h);
    }

  if (h->got.refcount > 0)
    {
      if (!pic_mode && h->dynindx == -1 && s390_h->tls_type >= GOT_TLS_IE)
        {
          if (s390_h->tls_type == GOT_TLS_IE_NLT)
            {
              h->got.offset = htab->elf.sgot->size;
              htab->elf.sgot->size += GOT_ENTRY_SIZE;
            }
          else
            h->got.offset = (bfd_vma) -1;
        }
      else
        {
          if (!ensure_dynamic_symbol(info, h))
            return false;

          asection *s_got = htab->elf.sgot;
          h->got.offset = s_got->size;
          s_got->size += GOT_ENTRY_SIZE;

          if (s390_h->tls_type == GOT_TLS_GD)
            s_got->size += GOT_ENTRY_SIZE;

          if ((s390_h->tls_type == GOT_TLS_GD && h->dynindx == -1)
              || s390_h->tls_type >= GOT_TLS_IE)
            htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
          else if (s390_h->tls_type == GOT_TLS_GD)
            htab->elf.srelgot->size += 2 * sizeof (Elf32_External_Rela);
          else if (!UNDEFWEAK_NO_DYNAMIC_RELOC (info, h)
                   && (pic_mode
                       || WILL_CALL_FINISH_DYNAMIC_SYMBOL (dynamic_sections_created, 0, h)))
            htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
        }
    }
  else
    h->got.offset = (bfd_vma) -1;

  if (h->dyn_relocs == NULL)
    return true;

  if (pic_mode)
    {
      if (SYMBOL_CALLS_LOCAL (info, h))
        {
          struct elf_dyn_relocs **pp = &h->dyn_relocs;
          struct elf_dyn_relocs *p;
          while ((p = *pp) != NULL)
            {
              p->count -= p->pc_count;
              p->pc_count = 0;
              if (p->count == 0)
                *pp = p->next;
              else
                pp = &p->next;
            }
        }

      if (h->dyn_relocs != NULL
          && h->root.type == bfd_link_hash_undefweak)
        {
          if (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
              || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
            h->dyn_relocs = NULL;
          else if (!ensure_dynamic_symbol(info, h))
            return false;
        }
    }
  else if (ELIMINATE_COPY_RELOCS)
    {
      bool keep_dyn_relocs = false;
      if (!h->non_got_ref
          && ((h->def_dynamic
               && !h->def_regular)
              || (dynamic_sections_created
                  && (h->root.type == bfd_link_hash_undefweak
                      || h->root.type == bfd_link_hash_undefined))))
        {
          if (!ensure_dynamic_symbol(info, h))
            return false;
          if (h->dynindx != -1)
            keep_dyn_relocs = true;
        }

      if (!keep_dyn_relocs)
        h->dyn_relocs = NULL;
    }

  struct elf_dyn_relocs *p;
  for (p = h->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (Elf32_External_Rela);
    }

  return true;
}

/* Set the sizes of the dynamic sections.  */

static void
calculate_local_dynrel_section_sizes (bfd *ibfd, struct bfd_link_info *info)
{
  for (asection *s = ibfd->sections; s != NULL; s = s->next)
    {
      for (struct elf_dyn_relocs *p = elf_section_data (s)->local_dynrel; p != NULL; p = p->next)
	{
	  if (!bfd_is_abs_section (p->sec) && bfd_is_abs_section (p->sec->output_section))
	    continue;

	  if (p->count != 0)
	    {
	      asection *srela = elf_section_data (p->sec)->sreloc;
	      if (srela == NULL)
	        continue;

	      srela->size += (bfd_size_type)p->count * sizeof (Elf32_External_Rela);
	      if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		info->flags |= DF_TEXTREL;
	    }
	}
    }
}

static void
process_local_got_entries (bfd *ibfd, struct bfd_link_info *info,
			   struct elf_s390_link_hash_table *htab)
{
  bfd_signed_vma *local_got = elf_local_got_refcounts (ibfd);
  if (local_got == NULL)
    return;

  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (ibfd);
  bfd_size_type locsymcount = symtab_hdr->sh_info;
  bfd_signed_vma *end_local_got = local_got + locsymcount;
  char *local_tls_type = elf_s390_local_got_tls_type (ibfd);

  asection *sgot = htab->elf.sgot;
  asection *srelgot = htab->elf.srelgot;

  if (sgot == NULL || srelgot == NULL)
    return;

  for (; local_got < end_local_got; ++local_got, ++local_tls_type)
    {
      if (*local_got > 0)
	{
	  *local_got = sgot->size;
	  sgot->size += GOT_ENTRY_SIZE;
	  if (*local_tls_type == GOT_TLS_GD)
		sgot->size += GOT_ENTRY_SIZE;
	  if (bfd_link_pic (info))
	    srelgot->size += sizeof (Elf32_External_Rela);
	}
      else
	*local_got = (bfd_vma) -1;
    }
}

static void
process_local_plt_entries (bfd *ibfd, struct elf_s390_link_hash_table *htab)
{
  struct plt_entry *local_plt = elf_s390_local_plt (ibfd);
  if (local_plt == NULL)
    return;

  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (ibfd);
  unsigned int locsymcount = symtab_hdr->sh_info;

  asection *iplt = htab->elf.iplt;
  asection *igotplt = htab->elf.igotplt;
  asection *irelplt = htab->elf.irelplt;

  if (iplt == NULL || igotplt == NULL || irelplt == NULL)
    return;

  for (unsigned int i = 0; i < locsymcount; i++)
    {
      if (local_plt[i].plt.refcount > 0)
	{
	  local_plt[i].plt.offset = iplt->size;
	  iplt->size += PLT_ENTRY_SIZE;
	  igotplt->size += GOT_ENTRY_SIZE;
	  irelplt->size += RELA_ENTRY_SIZE;
	}
      else
	local_plt[i].plt.offset = (bfd_vma) -1;
    }
}

static bool
allocate_dynamic_section_contents (bfd *dynobj,
                                   struct elf_s390_link_hash_table *htab,
                                   bool *has_relocs_out)
{
  *has_relocs_out = false;
  for (asection *s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      bool is_known_dynamic_section = false;
      if (s == htab->elf.splt
	  || s == htab->elf.sgot
	  || s == htab->elf.sgotplt
	  || s == htab->elf.sdynbss
	  || s == htab->elf.sdynrelro
	  || s == htab->elf.iplt
	  || s == htab->elf.igotplt
	  || s == htab->irelifunc)
        {
          is_known_dynamic_section = true;
        }
      else if (startswith (bfd_section_name (s), ".rela"))
	{
	  if (s->size != 0)
	    *has_relocs_out = true;
	  s->reloc_count = 0;
          is_known_dynamic_section = true;
	}

      if (!is_known_dynamic_section)
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
  return true;
}


static bool
elf_s390_late_size_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
			     struct bfd_link_info *info)
{
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  bfd *dynobj = htab->elf.dynobj;

  if (dynobj == NULL)
    return true;

  if (htab->elf.dynamic_sections_created)
    {
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  asection *interp_section = bfd_get_linker_section (dynobj, ".interp");
	  if (interp_section == NULL)
	    return false;

	  interp_section->size = sizeof ELF_DYNAMIC_INTERPRETER;
	  interp_section->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
	  interp_section->alloced = 1;
	}
    }

  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (!is_s390_elf (ibfd))
	continue;

      calculate_local_dynrel_section_sizes (ibfd, info);
      process_local_got_entries (ibfd, info, htab);
      process_local_plt_entries (ibfd, htab);
    }

  if (htab->tls_ldm_got.refcount > 0)
    {
      if (htab->elf.sgot == NULL || htab->elf.srelgot == NULL)
        return false;

      htab->tls_ldm_got.offset = htab->elf.sgot->size;
      htab->elf.sgot->size += 2 * GOT_ENTRY_SIZE;
      htab->elf.srelgot->size += sizeof (Elf32_External_Rela);
    }
  else
    htab->tls_ldm_got.offset = (bfd_vma) -1;

  elf_link_hash_traverse (&htab->elf, allocate_dynrelocs, info);

  bool relocs_needed = false;
  if (!allocate_dynamic_section_contents (dynobj, htab, &relocs_needed))
    return false;

  return _bfd_elf_add_dynamic_tags (output_bfd, info, relocs_needed);
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving @dtpoff relocation.
   This is PT_TLS segment p_vaddr.  */

static bfd_vma
dtpoff_base (struct bfd_link_info *info)
{
  /* The type of the value returned by elf_hash_table is assumed to be
     'struct bfd_elf_hash_table *' based on its usage. */
  struct bfd_elf_hash_table *h_table = elf_hash_table(info);

  if (h_table == NULL || h_table->tls_sec == NULL)
    return 0;

  return h_table->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
tpoff (struct bfd_link_info *info, bfd_vma address)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);

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
  const reloc_howto_type *howto;
  bfd_reloc_code reloc_type = (bfd_reloc_code) ELF32_R_TYPE (rel->r_info);

  howto = bfd_get_reloc_howto (input_bfd, reloc_type);

  if (howto == NULL)
    {
      _bfd_error_handler
        (_("%pB(%pA+%#" PRIx64 "): unknown or invalid TLS relocation type %u"),
         input_bfd,
         input_section,
         (uint64_t) rel->r_offset,
         (unsigned int) reloc_type);
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
emit_s390_dynamic_rela (bfd *output_bfd, asection *sreloc,
                        bfd_vma r_offset, unsigned long r_info, bfd_vma r_addend)
{
  Elf_Internal_Rela outrel;
  bfd_byte *loc;

  BFD_ASSERT (sreloc != NULL);

  outrel.r_offset = r_offset;
  outrel.r_info = r_info;
  outrel.r_addend = r_addend;

  loc = sreloc->contents;
  loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
  bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
  return true;
}

static int
emit_s390_tls_dynamic_relas (bfd *output_bfd, struct bfd_link_info *info,
                             struct elf_s390_link_hash_table *htab,
                             bfd_vma *local_got_offsets, unsigned long r_symndx,
                             struct elf_link_hash_entry *h, bfd_vma relocation_value,
                             unsigned int current_r_type, bfd_vma off, bool unresolved_reloc)
{
  BFD_ASSERT (htab->elf.srelgot != NULL);
  BFD_ASSERT (htab->elf.sgot != NULL);

  // If this is the first time setting this GOT entry, emit dynamic relocs.
  if ((off & 1) == 0)
    {
      int dr_type, indx;
      bfd_vma outrel_offset_got = (htab->elf.sgot->output_section->vma + htab->elf.sgot->output_offset + off);

      indx = h && h->dynindx != -1 ? h->dynindx : 0;
      if (current_r_type == R_390_TLS_GD32)
	dr_type = R_390_TLS_DTPMOD;
      else // R_390_TLS_IE32, R_390_TLS_GOTIE*, R_390_TLS_IEENT
	dr_type = R_390_TLS_TPOFF;

      bfd_vma addend_val = 0;
      if (dr_type == R_390_TLS_TPOFF && indx == 0)
	addend_val = relocation_value - dtpoff_base (info);

      if (!emit_s390_dynamic_rela (output_bfd, htab->elf.srelgot,
                                    outrel_offset_got,
                                    ELF32_R_INFO (indx, dr_type),
                                    addend_val))
	return false;

      if (current_r_type == R_390_TLS_GD32)
	{
	  if (indx == 0)
	    {
	      BFD_ASSERT (! unresolved_reloc);
	      bfd_put_32 (output_bfd, relocation_value - dtpoff_base (info),
			  htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
	    }
	  else
	    {
	      if (!emit_s390_dynamic_rela (output_bfd, htab->elf.srelgot,
                                            outrel_offset_got + GOT_ENTRY_SIZE,
                                            ELF32_R_INFO (indx, R_390_TLS_DTPOFF),
                                            0))
		return false;
	    }
	}

      if (h != NULL)
	h->got.offset |= 1;
      else
	local_got_offsets[r_symndx] |= 1;
    }
  return true;
}

static int
apply_final_relocation_and_handle_errors (bfd *output_bfd, struct bfd_link_info *info,
                                          bfd *input_bfd, asection *input_section,
                                          bfd_byte *contents, Elf_Internal_Rela *rel,
                                          reloc_howto_type *howto,
                                          bfd_vma relocation_value,
                                          struct elf_link_hash_entry *h, Elf_Internal_Sym *sym,
                                          asection *sec, Elf_Internal_Shdr *symtab_hdr,
                                          unsigned int r_type)
{
  bfd_reloc_status_type r_status;
  bfd_vma reloc_offset = rel->r_offset;
  bfd_vma reloc_addend = rel->r_addend;

  if (r_type == R_390_PC24DBL || r_type == R_390_PLT24DBL)
    reloc_offset--;

  if (r_type == R_390_20
      || r_type == R_390_GOT20
      || r_type == R_390_GOTPLT20
      || r_type == R_390_TLS_GOTIE20)
    {
      relocation_value += reloc_addend;
      relocation_value = (relocation_value & 0xfff) << 8 | (relocation_value & 0xff000) >> 12;
      r_status = _bfd_final_link_relocate (howto, input_bfd, input_section,
                                           contents, reloc_offset,
                                           relocation_value, 0);
    }
  else
    {
      r_status = _bfd_final_link_relocate (howto, input_bfd, input_section,
                                           contents, reloc_offset,
                                           relocation_value, reloc_addend);
    }

  if (r_status != bfd_reloc_ok)
    {
      const char *name;

      if (h != NULL)
        name = h->root.root.string;
      else
        {
          name = bfd_elf_string_from_elf_section (input_bfd,
                                                  symtab_hdr->sh_link,
                                                  sym->st_name);
          if (name == NULL)
            return false;
          if (*name == '\0')
            name = bfd_section_name (sec);
        }

      if (r_status == bfd_reloc_overflow)
        (*info->callbacks->reloc_overflow)
          (info, (h ? &h->root : NULL), name, howto->name,
           (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
      else
        {
          _bfd_error_handler
            (_("%pB(%pA+%#" PRIx64 "): reloc against `%s': error %d"),
             input_bfd, input_section,
             (uint64_t) rel->r_offset, name, (int) r_status);
          return false;
        }
    }
  return true;
}


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
  int ret_val = true;

  if (!is_s390_elf (input_bfd))
    {
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

  htab = elf_s390_hash_table (info);
  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);
  local_got_offsets = elf_local_got_offsets (input_bfd);

  BFD_ASSERT (htab != NULL);
  BFD_ASSERT (symtab_hdr != NULL);
  BFD_ASSERT (sym_hashes != NULL);
  // local_got_offsets may be NULL if no local GOT entries are present,
  // assertions are placed at points of access.

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      unsigned int r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      struct elf_link_hash_entry *h = NULL;
      Elf_Internal_Sym *sym = NULL;
      asection *sec = NULL;
      bfd_vma relocation_value = 0;
      bool unresolved_reloc = false;
      bool apply_final_relocation = true;
      bool skip_to_next_reloc_iteration = false;

      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_390_GNU_VTINHERIT || r_type == R_390_GNU_VTENTRY)
	continue;

      if (r_type >= R_390_max)
	{
	  bfd_set_error (bfd_error_bad_value);
	  ret_val = false;
	  break;
	}

      howto = elf_howto_table + r_type;
      r_symndx = ELF32_R_SYM (rel->r_info);

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];

	  if (ELF_ST_TYPE (sym->st_info) == STT_GNU_IFUNC)
	    {
	      struct plt_entry *local_plt = elf_s390_local_plt (input_bfd);
	      if (local_plt == NULL)
		{
		  bfd_set_error (bfd_error_no_memory);
		  ret_val = false;
		  break;
		}

	      relocation_value = (htab->elf.iplt->output_section->vma
				  + htab->elf.iplt->output_offset
				  + local_plt[r_symndx].plt.offset);

	      switch (r_type)
		{
		case R_390_PLTOFF16:
		case R_390_PLTOFF32:
		  relocation_value -= htab->elf.sgot->output_section->vma;
		  break;
		case R_390_GOTPLT12: case R_390_GOTPLT16: case R_390_GOTPLT20:
		case R_390_GOTPLT32: case R_390_GOTPLTENT: case R_390_GOT12:
		case R_390_GOT16: case R_390_GOT20: case R_390_GOT32:
		case R_390_GOTENT:
		  BFD_ASSERT (htab->elf.sgot != NULL && local_got_offsets != NULL);
		  bfd_put_32 (output_bfd, relocation_value,
			      htab->elf.sgot->contents + local_got_offsets[r_symndx]);
		  relocation_value = (local_got_offsets[r_symndx] + htab->elf.sgot->output_offset);
		  if (r_type == R_390_GOTENT || r_type == R_390_GOTPLTENT)
		    relocation_value += htab->elf.sgot->output_section->vma;
		  break;
		default:
		  break;
		}
	      local_plt[r_symndx].sec = sec;
	    }
	  else
	    relocation_value = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  bool warned ATTRIBUTE_UNUSED;
	  bool ignored ATTRIBUTE_UNUSED;
	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation_value,
				   unresolved_reloc, warned, ignored);
	}

      if (sec != NULL && discarded_section (sec))
	{
	  RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					   rel, 1, relend, R_390_NONE,
					   howto, 0, contents);
	}

      if (bfd_link_relocatable (info))
	continue;

      bool resolved_to_zero = (h != NULL && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));
      unsigned int original_r_type = r_type; // Store original type for comparison later

      switch (r_type)
	{
	case R_390_GOTPLT12: case R_390_GOTPLT16: case R_390_GOTPLT20:
	case R_390_GOTPLT32: case R_390_GOTPLTENT:
	  if (h != NULL && h->plt.offset != (bfd_vma) -1)
	    {
	      bfd_vma plt_index;
	      if (s390_is_ifunc_symbol_p (h))
		{
		  plt_index = h->plt.offset / PLT_ENTRY_SIZE;
		  relocation_value = (plt_index * GOT_ENTRY_SIZE + htab->elf.igotplt->output_offset);
		  if (r_type == R_390_GOTPLTENT)
		    relocation_value += htab->elf.igotplt->output_section->vma;
		}
	      else
		{
		  plt_index = (h->plt.offset - PLT_FIRST_ENTRY_SIZE) / PLT_ENTRY_SIZE;
		  relocation_value = (plt_index + 3) * GOT_ENTRY_SIZE;
		  if (r_type == R_390_GOTPLTENT)
		    relocation_value += htab->elf.sgot->output_section->vma;
		}
	      unresolved_reloc = false;
	    }
	  // Fall through for GOT logic

	case R_390_GOT12: case R_390_GOT16: case R_390_GOT20:
	case R_390_GOT32: case R_390_GOTENT:
	  {
	    bfd_vma off;
	    BFD_ASSERT (htab->elf.sgot != NULL);
	    asection *base_got_sec = htab->elf.sgot;

	    if (h != NULL)
	      {
		bool dyn = htab->elf.dynamic_sections_created;
		off = h->got.offset;

		if (s390_is_ifunc_symbol_p (h))
		  {
		    BFD_ASSERT (h->plt.offset != (bfd_vma) -1);
		    if (off == (bfd_vma)-1)
		      {
			base_got_sec = htab->elf.igotplt;
			off = h->plt.offset / PLT_ENTRY_SIZE * GOT_ENTRY_SIZE;
		      }
		  }
		else if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, bfd_link_pic (info), h)
			 || SYMBOL_REFERENCES_LOCAL (info, h) || resolved_to_zero)
		  {
		    if ((off & 1) != 0)
		      off &= ~1;
		    else
		      {
			bfd_put_32 (output_bfd, relocation_value, base_got_sec->contents + off);
			h->got.offset |= 1;
		      }

		    if ((h->def_regular && SYMBOL_REFERENCES_LOCAL (info, h))
			&& ((r_type == R_390_GOTENT
			     && (bfd_get_16 (input_bfd, contents + rel->r_offset - 2) & 0xff0f) == 0xc40d)
			    || (r_type == R_390_GOT20
				&& (bfd_get_32 (input_bfd, contents + rel->r_offset - 2) & 0xff00f000) == 0xe300c000
				&& bfd_get_8 (input_bfd, contents + rel->r_offset + 3) == 0x58)))
		      {
			unsigned short new_insn = (0xc000 | (bfd_get_8 (input_bfd, contents + rel->r_offset - 1) & 0xf0));
			bfd_put_16 (output_bfd, new_insn, contents + rel->r_offset - 2);
			r_type = R_390_PC32DBL;
			howto = elf_howto_table + r_type;
			rel->r_addend = 2;
			relocation_value = h->root.u.def.value + h->root.u.def.section->output_section->vma + h->root.u.def.section->output_offset;
		      }
		  }
		else
		  unresolved_reloc = false;
	      }
	    else
	      {
		BFD_ASSERT (local_got_offsets != NULL);
		off = local_got_offsets[r_symndx];

		if ((off & 1) != 0)
		  off &= ~1;
		else
		  {
		    bfd_put_32 (output_bfd, relocation_value, htab->elf.sgot->contents + off);
		    if (bfd_link_pic (info))
		      {
			BFD_ASSERT (htab->elf.srelgot != NULL);
			if (!emit_s390_dynamic_rela (output_bfd, htab->elf.srelgot,
                                                      (htab->elf.sgot->output_section->vma + htab->elf.sgot->output_offset + off),
                                                      ELF32_R_INFO (0, R_390_RELATIVE),
                                                      relocation_value))
                            { ret_val = false; break; }
		      }
		    local_got_offsets[r_symndx] |= 1;
		  }
	      }
	    BFD_ASSERT (off < (bfd_vma) -2);

	    relocation_value = base_got_sec->output_offset + off;
	    if (r_type == R_390_GOTENT || r_type == R_390_GOTPLTENT)
	      relocation_value += base_got_sec->output_section->vma;
	    break;
	  }

	case R_390_GOTOFF16:
	case R_390_GOTOFF32:
	  if (h != NULL && s390_is_ifunc_symbol_p (h) && h->def_regular && !bfd_link_executable (info))
	    {
	      relocation_value = (htab->elf.iplt->output_section->vma + htab->elf.iplt->output_offset
				  + h->plt.offset - htab->elf.sgot->output_section->vma);
	    }
	  else
	    relocation_value -= htab->elf.sgot->output_section->vma;
	  break;

	case R_390_GOTPC:
	case R_390_GOTPCDBL:
	  relocation_value = htab->elf.sgot->output_section->vma;
	  unresolved_reloc = false;
	  break;

	case R_390_PLT12DBL: case R_390_PLT16DBL: case R_390_PLT24DBL:
	case R_390_PLT32DBL: case R_390_PLT32:
	  if (h == NULL || h->plt.offset == (bfd_vma) -1
	      || (htab->elf.splt == NULL && htab->elf.iplt == NULL))
	    break;
	  if (s390_is_ifunc_symbol_p (h))
	    relocation_value = (htab->elf.iplt->output_section->vma + htab->elf.iplt->output_offset + h->plt.offset);
	  else
	    relocation_value = (htab->elf.splt->output_section->vma + htab->elf.splt->output_offset + h->plt.offset);
	  unresolved_reloc = false;
	  break;

	case R_390_PLTOFF16:
	case R_390_PLTOFF32:
	  if (h == NULL || h->plt.offset == (bfd_vma) -1
	      || (htab->elf.splt == NULL && !s390_is_ifunc_symbol_p (h)))
	    {
	      relocation_value -= htab->elf.sgot->output_section->vma;
	      break;
	    }
	  if (s390_is_ifunc_symbol_p (h))
	    relocation_value = (htab->elf.iplt->output_section->vma + htab->elf.iplt->output_offset
				+ h->plt.offset - htab->elf.sgot->output_section->vma);
	  else
	    relocation_value = (htab->elf.splt->output_section->vma + htab->elf.splt->output_offset
				+ h->plt.offset - htab->elf.sgot->output_section->vma);
	  unresolved_reloc = false;
	  break;

	case R_390_PC16: case R_390_PC12DBL: case R_390_PC16DBL:
	case R_390_PC24DBL: case R_390_PC32DBL: case R_390_PC32:
	  if (h != NULL && s390_is_ifunc_symbol_p (h) && h->def_regular && !bfd_link_executable (info))
	    {
	      relocation_value = (htab->elf.iplt->output_section->vma + htab->elf.iplt->output_offset + h->plt.offset);
	    }
	  // Fall through.

	case R_390_8: case R_390_16: case R_390_32:
	  if ((input_section->flags & SEC_ALLOC) == 0)
	    break;

	  if (h != NULL && s390_is_ifunc_symbol_p (h) && h->def_regular)
	    {
	      if (!bfd_link_pic (info))
		{
		  relocation_value = (htab->elf.iplt->output_section->vma + htab->elf.iplt->output_offset + h->plt.offset);
		}
	      else
		{
		  bfd_vma outrel_offset_calc = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);
		  if (outrel_offset_calc == (bfd_vma) -1 || outrel_offset_calc == (bfd_vma) -2)
		    {
		      skip_to_next_reloc_iteration = true; apply_final_relocation = false; break;
		    }
                  outrel_offset_calc += (input_section->output_section->vma + input_section->output_offset);

		  unsigned long r_info_val;
		  bfd_vma r_addend_val;
		  if (h->dynindx == -1 || h->forced_local || bfd_link_executable (info))
		    { r_info_val = ELF32_R_INFO (0, R_390_IRELATIVE); r_addend_val = (h->root.u.def.value + h->root.u.def.section->output_section->vma + h->root.u.def.section->output_offset); }
		  else
		    { r_info_val = ELF32_R_INFO (h->dynindx, r_type); r_addend_val = 0; }

                  BFD_ASSERT (htab->elf.irelifunc != NULL);
		  if (!emit_s390_dynamic_rela (output_bfd, htab->elf.irelifunc, outrel_offset_calc, r_info_val, r_addend_val))
                      { ret_val = false; break; }

		  skip_to_next_reloc_iteration = true; apply_final_relocation = false; break;
		}
	    }
	  // If we decided to skip above, break now.
	  if (skip_to_next_reloc_iteration) break;

	  if ((bfd_link_pic (info)
	       && (h == NULL || (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT && !resolved_to_zero)
		   || h->root.type != bfd_link_hash_undefweak)
	       && ((r_type != R_390_PC16 && r_type != R_390_PC12DBL && r_type != R_390_PC16DBL
		    && r_type != R_390_PC24DBL && r_type != R_390_PC32DBL && r_type != R_390_PC32)
		   || !SYMBOL_CALLS_LOCAL (info, h)))
	      || (ELIMINATE_COPY_RELOCS && !bfd_link_pic (info) && h != NULL && h->dynindx != -1
		  && !h->non_got_ref && ((h->def_dynamic && !h->def_regular)
					 || h->root.type == bfd_link_hash_undefweak
					 || h->root.type == bfd_link_hash_undefined)))
	    {
	      bfd_vma outrel_offset_calc = _bfd_elf_section_offset (output_bfd, info, input_section, rel->r_offset);
	      bool relocate_for_dynamic = false;

	      if (outrel_offset_calc == (bfd_vma) -1)
		{ skip_to_next_reloc_iteration = true; apply_final_relocation = false; break; }
	      else if (outrel_offset_calc == (bfd_vma) -2)
		{ relocate_for_dynamic = true; }

              outrel_offset_calc += (input_section->output_section->vma + input_section->output_offset);

	      unsigned long r_info_val;
	      bfd_vma r_addend_val;
	      if (h != NULL && h->dynindx != -1
		  && (r_type == R_390_PC16 || r_type == R_390_PC12DBL || r_type == R_390_PC16DBL
		      || r_type == R_390_PC24DBL || r_type == R_390_PC32DBL || r_type == R_390_PC32
		      || !bfd_link_pic (info) || !SYMBOLIC_BIND (info, h) || !h->def_regular))
		{ r_info_val = ELF32_R_INFO (h->dynindx, r_type); r_addend_val = rel->r_addend; }
	      else
		{
		  r_addend_val = relocation_value + rel->r_addend;
		  if (r_type == R_390_32)
		    { relocate_for_dynamic = true; r_info_val = ELF32_R_INFO (0, R_390_RELATIVE); }
		  else
		    {
		      long sindx;
		      if (bfd_is_abs_section (sec)) sindx = 0;
		      else if (sec == NULL || sec->owner == NULL)
			{ bfd_set_error(bfd_error_bad_value); ret_val = false; skip_to_next_reloc_iteration = true; apply_final_relocation = false; break; }
		      else
			{
			  asection *osec = sec->output_section;
			  sindx = elf_section_data (osec)->dynindx;
			  if (sindx == 0) { osec = htab->elf.text_index_section; sindx = elf_section_data (osec)->dynindx; }
			  BFD_ASSERT (sindx != 0);
			  r_addend_val -= osec->vma;
			}
		      r_info_val = ELF32_R_INFO (sindx, r_type);
		    }
		}
              BFD_ASSERT (elf_section_data (input_section)->sreloc != NULL);
	      if (!emit_s390_dynamic_rela (output_bfd, elf_section_data (input_section)->sreloc, outrel_offset_calc, r_info_val, r_addend_val))
                  { ret_val = false; break; }

	      if (!relocate_for_dynamic)
		{ skip_to_next_reloc_iteration = true; apply_final_relocation = false; break; }
	    }
	  break;

	case R_390_TLS_IE32:
	  if (bfd_link_pic (info))
	    {
	      bfd_vma outrel_offset_calc = rel->r_offset + input_section->output_section->vma + input_section->output_offset;
              BFD_ASSERT (elf_section_data (input_section)->sreloc != NULL);
              if (!emit_s390_dynamic_rela (output_bfd, elf_section_data (input_section)->sreloc, outrel_offset_calc, ELF32_R_INFO (0, R_390_RELATIVE), relocation_value))
                  { ret_val = false; break; }
	    }
	  // Fall through.
	case R_390_TLS_GD32:
	case R_390_TLS_GOTIE32:
	  {
	    int tls_type_val;
            unsigned int current_r_type_val = elf_s390_tls_transition (info, r_type, h == NULL);
	    tls_type_val = GOT_UNKNOWN;
	    if (h == NULL && local_got_offsets)
	      tls_type_val = elf_s390_local_got_tls_type (input_bfd) [r_symndx];
	    else if (h != NULL)
	      {
		tls_type_val = elf_s390_hash_entry(h)->tls_type;
		if (!bfd_link_pic (info) && h->dynindx == -1 && tls_type_val >= GOT_TLS_IE)
		  current_r_type_val = R_390_TLS_LE32;
	      }
	    if (current_r_type_val == R_390_TLS_GD32 && tls_type_val >= GOT_TLS_IE)
	      current_r_type_val = R_390_TLS_IE32;

	    if (current_r_type_val == R_390_TLS_LE32)
	      {
		BFD_ASSERT (! unresolved_reloc);
		bfd_put_32 (output_bfd, -tpoff (info, relocation_value) + rel->r_addend, contents + rel->r_offset);
		skip_to_next_reloc_iteration = true; apply_final_relocation = false; break;
	      }

	    BFD_ASSERT (htab->elf.sgot != NULL);
	    bfd_vma off;
	    if (h != NULL) off = h->got.offset;
	    else { BFD_ASSERT (local_got_offsets != NULL); off = local_got_offsets[r_symndx]; }

	    if (!emit_s390_tls_dynamic_relas (output_bfd, info, htab, local_got_offsets, r_symndx, h,
                                              relocation_value, current_r_type_val, off, unresolved_reloc))
                { ret_val = false; break; }

	    BFD_ASSERT (off < (bfd_vma) -2);

	    if (current_r_type_val == original_r_type)
	      {
		relocation_value = htab->elf.sgot->output_offset + off;
		if (current_r_type_val == R_390_TLS_IE32 || current_r_type_val == R_390_TLS_IEENT)
		  relocation_value += htab->elf.sgot->output_section->vma;
		unresolved_reloc = false;
	      }
	    else
	      {
		bfd_put_32 (output_bfd, htab->elf.sgot->output_offset + off, contents + rel->r_offset);
		skip_to_next_reloc_iteration = true; apply_final_relocation = false; break;
	      }
	    break;
	  }

	case R_390_TLS_GOTIE12: case R_390_TLS_GOTIE20: case R_390_TLS_IEENT:
	  {
	    bfd_vma off;
	    int tls_type_val = GOT_UNKNOWN;
	    bool emit_dyn_rel_needed = false;

	    if (h == NULL)
	      {
		BFD_ASSERT (local_got_offsets != NULL);
		off = local_got_offsets[r_symndx];
		if (bfd_link_pic (info))
		  emit_dyn_rel_needed = true;
	      }
	    else
	      {
		off = h->got.offset;
		tls_type_val = elf_s390_hash_entry(h)->tls_type;
		if (bfd_link_pic (info) || h->dynindx != -1 || tls_type_val < GOT_TLS_IE)
		  emit_dyn_rel_needed = true;
	      }

	    if (emit_dyn_rel_needed)
	      {
		if (!emit_s390_tls_dynamic_relas (output_bfd, info, htab, local_got_offsets, r_symndx, h,
                                                  relocation_value, r_type, off, unresolved_reloc))
                    { ret_val = false; break; }
	      }
	    else
	      {
		BFD_ASSERT (htab->elf.sgot != NULL);
		BFD_ASSERT (! unresolved_reloc);
		bfd_put_32 (output_bfd, -tpoff (info, relocation_value), htab->elf.sgot->contents + off);
	      }

	    BFD_ASSERT (htab->elf.sgot != NULL);
	    relocation_value = htab->elf.sgot->output_offset + off;
	    if (r_type == R_390_TLS_IEENT)
	      relocation_value += htab->elf.sgot->output_section->vma;
	    unresolved_reloc = false;
	    break;
	  }

	case R_390_TLS_LDM32:
	  if (! bfd_link_pic (info))
	    { skip_to_next_reloc_iteration = true; apply_final_relocation = false; break; }

	  BFD_ASSERT (htab->elf.sgot != NULL);
	  bfd_vma off_ldm = htab->tls_ldm_got.offset;
	  if ((off_ldm & 1) == 0)
	    {
	      BFD_ASSERT (htab->elf.srelgot != NULL);
	      bfd_vma outrel_offset_got = (htab->elf.sgot->output_section->vma + htab->elf.sgot->output_offset + off_ldm);
	      bfd_put_32 (output_bfd, 0, htab->elf.sgot->contents + off_ldm + GOT_ENTRY_SIZE);

	      if (!emit_s390_dynamic_rela (output_bfd, htab->elf.srelgot, outrel_offset_got,
                                            ELF32_R_INFO (0, R_390_TLS_DTPMOD), 0))
                  { ret_val = false; break; }
	      htab->tls_ldm_got.offset |= 1;
	    }
	  relocation_value = htab->elf.sgot->output_offset + off_ldm;
	  unresolved_reloc = false;
	  break;

	case R_390_TLS_LE32:
	  if (bfd_link_dll (info))
	    {
	      bfd_vma outrel_offset_calc = rel->r_offset + input_section->output_section->vma + input_section->output_offset;
	      int indx = (h != NULL && h->dynindx != -1) ? h->dynindx : 0;
	      bfd_vma addend_val = (indx == 0) ? (relocation_value - dtpoff_base (info)) : 0;
              BFD_ASSERT (elf_section_data (input_section)->sreloc != NULL);
	      if (!emit_s390_dynamic_rela (output_bfd, elf_section_data (input_section)->sreloc, outrel_offset_calc, ELF32_R_INFO (indx, R_390_TLS_TPOFF), addend_val))
                  { ret_val = false; break; }
	    }
	  else
	    {
	      BFD_ASSERT (! unresolved_reloc);
	      bfd_put_32 (output_bfd, -tpoff (info, relocation_value) + rel->r_addend, contents + rel->r_offset);
	    }
	  skip_to_next_reloc_iteration = true; apply_final_relocation = false; break;

	case R_390_TLS_LDO32:
	  if (bfd_link_pic (info) || (input_section->flags & SEC_DEBUGGING))
	    relocation_value -= dtpoff_base (info);
	  else
	    relocation_value = -tpoff (info, relocation_value);
	  break;

	case R_390_TLS_LOAD: case R_390_TLS_GDCALL: case R_390_TLS_LDCALL:
	  {
	    int tls_type_val = GOT_UNKNOWN;
	    if (h == NULL && local_got_offsets)
	      tls_type_val = elf_s390_local_got_tls_type (input_bfd) [r_symndx];
	    else if (h != NULL)
	      tls_type_val = elf_s390_hash_entry(h)->tls_type;

	    if (tls_type_val == GOT_TLS_GD)
	      { skip_to_next_reloc_iteration = true; apply_final_relocation = false; break; }

	    if (r_type == R_390_TLS_LOAD)
	      {
		if (!bfd_link_pic (info) && (h == NULL || h->dynindx == -1))
		  {
		    unsigned int insn, ry;
		    insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
		    if ((insn & 0xff00f000) == 0x58000000) ry = (insn & 0x000f0000);
		    else if ((insn & 0xff0f0000) == 0x58000000) ry = (insn & 0x0000f000) << 4;
		    else if ((insn & 0xff00f000) == 0x5800c000) ry = (insn & 0x000f0000);
		    else if ((insn & 0xff0f0000) == 0x580c0000) ry = (insn & 0x0000f000) << 4;
		    else { if (!invalid_tls_insn (input_bfd, input_section, rel)) { ret_val = false; break; } }
		    insn = 0x18000700 | (insn & 0x00f00000) | ry;
		    bfd_put_32 (output_bfd, insn, contents + rel->r_offset);
		  }
	      }
	    else if (r_type == R_390_TLS_GDCALL)
	      {
		unsigned int insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
		if ((insn & 0xff000fff) != 0x4d000000 && (insn & 0xffff0000) != 0xc0e50000 && (insn & 0xff000000) != 0x0d000000)
		  { if (!invalid_tls_insn (input_bfd, input_section, rel)) { ret_val = false; break; } }
		if (!bfd_link_pic (info) && (h == NULL || h->dynindx == -1))
		  {
		    if ((insn & 0xff000000) == 0x0d000000) insn = 0x07070000 | (insn & 0xffff);
		    else if ((insn & 0xff000000) == 0x4d000000) insn = 0x47000000;
		    else { insn = 0xc0040000; bfd_put_16 (output_bfd, 0x0000, contents + rel->r_offset + 4); }
		  }
		else
		  {
		    if ((insn & 0xff000000) == 0x0d000000)
		      { if (!invalid_tls_insn (input_bfd, input_section, rel)) { ret_val = false; break; } }
		    else if ((insn & 0xff000000) == 0x4d000000) insn = 0x5822c000;
		    else { insn = 0x5822c000; bfd_put_16 (output_bfd, 0x0700, contents + rel->r_offset + 4); }
		  }
		bfd_put_32 (output_bfd, insn, contents + rel->r_offset);
	      }
	    else if (r_type == R_390_TLS_LDCALL)
	      {
		if (!bfd_link_pic (info))
		  {
		    unsigned int insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
		    if ((insn & 0xff000fff) != 0x4d000000 && (insn & 0xffff0000) != 0xc0e50000 && (insn & 0xff000000) != 0x0d000000)
		      { if (!invalid_tls_insn (input_bfd, input_section, rel)) { ret_val = false; break; } }
		    if ((insn & 0xff000000) == 0x0d000000) insn = 0x07070000 | (insn & 0xffff);
		    else if ((insn & 0xff000000) == 0x4d000000) insn = 0x47000000;
		    else { insn = 0xc0040000; bfd_put_16 (output_bfd, 0x0000, contents + rel->r_offset + 4); }
		    bfd_put_32 (output_bfd, insn, contents + rel->r_offset);
		  }
	      }
	    skip_to_next_reloc_iteration = true; apply_final_relocation = false; break;
	  }

	default:
	  break;
	}

      if (ret_val == false)
          break;

      if (unresolved_reloc
	  && !((input_section->flags & SEC_DEBUGGING) != 0 && h->def_dynamic)
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      rel->r_offset) != (bfd_vma) -1)
	{
	  _bfd_error_handler
	    (_("%pB(%pA+%#" PRIx64 "): unresolvable %s relocation against symbol `%s'"),
	     input_bfd, input_section, (uint64_t) rel->r_offset, howto->name, h->root.root.string);
	}

      if (apply_final_relocation && !skip_to_next_reloc_iteration)
	{
	  if (!apply_final_relocation_and_handle_errors (output_bfd, info, input_bfd, input_section,
                                                          contents, rel, howto,
                                                          relocation_value, h, sym, sec, symtab_hdr, r_type))
	    {
	      ret_val = false;
	      break;
	    }
	}
      if (skip_to_next_reloc_iteration)
        continue;
    }

  return ret_val;
}

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
  asection *plt, *gotplt, *relplt;
  bfd_vma relative_offset;

  if (htab->elf.iplt == NULL
      || htab->elf.igotplt == NULL
      || htab->elf.irelplt == NULL)
    abort ();

  gotplt = htab->elf.igotplt;
  relplt = htab->elf.irelplt;
  plt = htab->elf.iplt;

  iplt_index = iplt_offset / PLT_ENTRY_SIZE;
  igotiplt_offset = iplt_index * GOT_ENTRY_SIZE;
  got_offset = igotiplt_offset + gotplt->output_offset;

  relative_offset = - (plt->output_offset +
		       (PLT_ENTRY_SIZE * iplt_index) + 18) / 2;

  const int S390_MAX_RELATIVE_OFFSET_SIGNED = 32768;
  const unsigned int S390_HALFWORD_JUMP_RANGE_BYTES = 65536;

  if ( -S390_MAX_RELATIVE_OFFSET_SIGNED > (int) relative_offset )
    relative_offset
      = -(unsigned) (((S390_HALFWORD_JUMP_RANGE_BYTES / PLT_ENTRY_SIZE - 1) * PLT_ENTRY_SIZE) / 2);

  const bfd_vma PLT_JUMP_OFFSET_FIELD_OFFSET = 20;
  const bfd_vma PLT_GOT_OFFSET_FIELD_OFFSET = 24;
  const bfd_vma PLT_RELA_TABLE_ADDRESS_OFFSET = 28;

  if (!bfd_link_pic (info))
    {
      memcpy (plt->contents + iplt_offset, elf_s390_plt_entry,
	      PLT_ENTRY_SIZE);

      bfd_put_32 (output_bfd,
		  (gotplt->output_section->vma
		   + got_offset),
		  plt->contents + iplt_offset + PLT_GOT_OFFSET_FIELD_OFFSET);
    }
  else
    {
      const bfd_vma GOT_OFFSET_DISPLACEMENT_THRESHOLD = 4096;
      const bfd_vma GOT_OFFSET_IMMEDIATE_THRESHOLD = 32768;
      const bfd_vma PLT_PIC12_DISPLACEMENT_MASK = 0xc000;
      const bfd_vma PLT_PIC_GOT_OFFSET_INSTRUCTION_OFFSET = 2;

      if (got_offset < GOT_OFFSET_DISPLACEMENT_THRESHOLD)
	{
	  memcpy (plt->contents + iplt_offset,
		  elf_s390_plt_pic12_entry,
		  PLT_ENTRY_SIZE);

	  bfd_put_16 (output_bfd, PLT_PIC12_DISPLACEMENT_MASK | got_offset,
		      plt->contents + iplt_offset + PLT_PIC_GOT_OFFSET_INSTRUCTION_OFFSET);
	}
      else if (got_offset < GOT_OFFSET_IMMEDIATE_THRESHOLD)
	{
	  memcpy (plt->contents + iplt_offset,
		  elf_s390_plt_pic16_entry,
		  PLT_ENTRY_SIZE);

	  bfd_put_16 (output_bfd, got_offset,
		      plt->contents + iplt_offset + PLT_PIC_GOT_OFFSET_INSTRUCTION_OFFSET);
	}
      else
	{
	  memcpy (plt->contents + iplt_offset,
		  elf_s390_plt_pic_entry,
		  PLT_ENTRY_SIZE);

	  bfd_put_32 (output_bfd, got_offset,
		      plt->contents + iplt_offset + PLT_GOT_OFFSET_FIELD_OFFSET);
	}
    }

  bfd_put_32 (output_bfd, (relative_offset << 16),
	      plt->contents + iplt_offset + PLT_JUMP_OFFSET_FIELD_OFFSET);

  bfd_put_32 (output_bfd, relplt->output_offset +
	      iplt_index * RELA_ENTRY_SIZE,
	      plt->contents + iplt_offset + PLT_RELA_TABLE_ADDRESS_OFFSET);

  const bfd_vma GOT_ENTRY_TARGET_INSTRUCTION_OFFSET = 12;
  bfd_put_32 (output_bfd,
	      (plt->output_section->vma
	       + plt->output_offset
	       + iplt_offset
	       + GOT_ENTRY_TARGET_INSTRUCTION_OFFSET),
	      gotplt->contents + igotiplt_offset);

  rela.r_offset = gotplt->output_section->vma + got_offset;

  if (h == NULL
      || h->dynindx == -1
      || ((bfd_link_executable (info)
	   || ELF_ST_VISIBILITY (h->other) != STV_DEFAULT)
	  && h->def_regular))
    {
      rela.r_info = ELF32_R_INFO (0, R_390_IRELATIVE);
      rela.r_addend = resolver_address;
    }
  else
    {
      rela.r_info = ELF32_R_INFO (h->dynindx, R_390_JMP_SLOT);
      rela.r_addend = 0;
    }

  bfd_byte *loc = relplt->contents + iplt_index * RELA_ENTRY_SIZE;
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
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry*)h;

  if (h->plt.offset != (bfd_vma) -1)
    {
      if (htab->elf.splt == NULL || htab->elf.sgotplt == NULL || htab->elf.srelplt == NULL)
        {
          _bfd_error_handler (_("PLT required sections (splt, sgotplt, srelplt) not found for symbol '%s'"), h->root.root.string);
          return false;
        }

      if (s390_is_ifunc_symbol_p (h) && h->def_regular)
	{
	  if (!elf_s390_finish_ifunc_symbol (output_bfd, info, h,
	    htab, h->plt.offset,
	    eh->ifunc_resolver_address +
	    eh->ifunc_resolver_section->output_offset +
	    eh->ifunc_resolver_section->output_section->vma))
        {
            return false;
        }
	}
      else
	{
	  if (h->dynindx == -1)
	    {
	      _bfd_error_handler (_("Symbol '%s' has PLT entry but no dynamic index"), h->root.root.string);
	      return false;
	    }

	  bfd_vma plt_index;
	  bfd_vma got_offset;
	  long plt_branch_offset;
	  Elf_Internal_Rela rela;
	  bfd_byte *loc;

	  plt_index = (h->plt.offset - PLT_FIRST_ENTRY_SIZE) / PLT_ENTRY_SIZE;
	  got_offset = (plt_index + 3) * GOT_ENTRY_SIZE;

	  plt_branch_offset = - ((long)(PLT_FIRST_ENTRY_SIZE +
				(PLT_ENTRY_SIZE * plt_index) + 18) / 2);

	  if (plt_branch_offset < -32768L)
	    plt_branch_offset = -(((long)65536 / PLT_ENTRY_SIZE - 1) * PLT_ENTRY_SIZE / 2);

          const bfd_byte *plt_template;
          int template_offset_for_got_val = -1;
          int template_offset_for_disp_val = -1;
          bfd_vma disp_val = 0;

	  if (!bfd_link_pic (info))
	    {
	      plt_template = elf_s390_plt_entry;
              template_offset_for_got_val = 24;
	    }
	  else if (got_offset < 4096)
	    {
	      plt_template = elf_s390_plt_pic12_entry;
              template_offset_for_disp_val = 2;
              disp_val = (bfd_vma)0xc000 | got_offset;
	    }
	  else if (got_offset < 32768)
	    {
	      plt_template = elf_s390_plt_pic16_entry;
              template_offset_for_disp_val = 2;
              disp_val = got_offset;
	    }
	  else
	    {
	      plt_template = elf_s390_plt_pic_entry;
              template_offset_for_got_val = 24;
	    }

          memcpy (htab->elf.splt->contents + h->plt.offset, plt_template, PLT_ENTRY_SIZE);

          bfd_put_32 (output_bfd, (bfd_vma) (plt_branch_offset << 16),
                      htab->elf.splt->contents + h->plt.offset + 20);

          if (template_offset_for_got_val != -1)
            {
              bfd_put_32 (output_bfd,
                          (htab->elf.sgotplt->output_section->vma
                           + htab->elf.sgotplt->output_offset
                           + got_offset),
                          htab->elf.splt->contents + h->plt.offset + template_offset_for_got_val);
            }
          else if (template_offset_for_disp_val != -1)
            {
              bfd_put_16 (output_bfd, disp_val,
                          htab->elf.splt->contents + h->plt.offset + template_offset_for_disp_val);
            }

	  bfd_put_32 (output_bfd, plt_index * sizeof (Elf32_External_Rela),
		      htab->elf.splt->contents + h->plt.offset + 28);

	  bfd_put_32 (output_bfd,
		      (htab->elf.splt->output_section->vma
		       + htab->elf.splt->output_offset
		       + h->plt.offset
		       + 12),
		      htab->elf.sgotplt->contents + got_offset);

	  rela.r_offset = (htab->elf.sgotplt->output_section->vma
			   + htab->elf.sgotplt->output_offset
			   + got_offset);
	  rela.r_info = ELF32_R_INFO (h->dynindx, R_390_JMP_SLOT);
	  rela.r_addend = 0;
	  loc = htab->elf.srelplt->contents + plt_index * sizeof (Elf32_External_Rela);
	  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

	  if (!h->def_regular)
	    {
	      sym->st_shndx = SHN_UNDEF;
	    }
	}
    }

  if (h->got.offset != (bfd_vma) -1
      && elf_s390_hash_entry(h)->tls_type != GOT_TLS_GD
      && elf_s390_hash_entry(h)->tls_type != GOT_TLS_IE
      && elf_s390_hash_entry(h)->tls_type != GOT_TLS_IE_NLT)
    {
      if (htab->elf.sgot == NULL || htab->elf.srelgot == NULL)
        {
          _bfd_error_handler (_("GOT required sections (sgot, srelgot) not found for symbol '%s'"), h->root.root.string);
          return false;
        }

      Elf_Internal_Rela rela;
      bfd_byte *loc;
      bool emit_rela = true;
      bool is_glob_dat_path = false;

      rela.r_offset = (htab->elf.sgot->output_section->vma
                       + htab->elf.sgot->output_offset
                       + (h->got.offset &~ (bfd_vma) 1));

      if (h->def_regular && s390_is_ifunc_symbol_p (h))
	{
	  if (bfd_link_pic (info))
	    {
	      is_glob_dat_path = true;
	    }
	  else
	    {
	      bfd_put_32 (output_bfd, (htab->elf.iplt->output_section->vma
				       + htab->elf.iplt->output_offset
				       + h->plt.offset),
			  htab->elf.sgot->contents + h->got.offset);
	      emit_rela = false;
	    }
	}
      else if (SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  if (UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    {
	      emit_rela = false;
	    }
	  else if (!(h->def_regular || ELF_COMMON_DEF_P (h)))
	    {
	      _bfd_error_handler (_("Symbol '%s' references local but is neither regular def nor common def"), h->root.root.string);
	      return false;
	    }
          else
            {
	      BFD_ASSERT((h->got.offset & 1) != 0);
	      rela.r_info = ELF32_R_INFO (0, R_390_RELATIVE);
	      rela.r_addend = (h->root.u.def.value
			       + h->root.u.def.section->output_section->vma
			       + h->root.u.def.section->output_offset);
            }
	}
      else
	{
	  is_glob_dat_path = true;
	}

      if (is_glob_dat_path && emit_rela)
        {
          BFD_ASSERT((h->got.offset & 1) == 0);
          bfd_put_32 (output_bfd, (bfd_vma) 0, htab->elf.sgot->contents + h->got.offset);
          rela.r_info = ELF32_R_INFO (h->dynindx, R_390_GLOB_DAT);
          rela.r_addend = 0;
        }

      if (emit_rela)
        {
          loc = htab->elf.srelgot->contents;
          loc += htab->elf.srelgot->reloc_count++ * sizeof (Elf32_External_Rela);
          bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
        }
    }

  if (h->needs_copy)
    {
      if (h->dynindx == -1
	  || (h->root.type != bfd_link_hash_defined
	      && h->root.type != bfd_link_hash_defweak)
	  || htab->elf.srelbss == NULL
	  || htab->elf.sreldynrelro == NULL)
        {
          _bfd_error_handler (_("Symbol '%s' needs COPY reloc but required conditions not met"), h->root.root.string);
          return false;
        }

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
      loc = s->contents + s->reloc_count++ * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
    }

  if (h == htab->elf.hdynamic
      || h == htab->elf.hgot
      || h == htab->elf.hplt)
    sym->st_shndx = SHN_ABS;

  return true;
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

static enum elf_reloc_type_class
elf_s390_reloc_type_class (const struct bfd_link_info *info,
			   const asection *rel_sec ATTRIBUTE_UNUSED,
			   const Elf_Internal_Rela *rela)
{
  bfd *abfd = info->output_bfd;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  unsigned long r_symndx = ELF32_R_SYM (rela->r_info);
  Elf_Internal_Sym sym;

  if (bed == NULL || bed->s == NULL)
    {
      return reloc_class_normal;
    }

  if (htab == NULL || htab->elf.dynsym == NULL || htab->elf.dynsym->contents == NULL)
    {
      return reloc_class_normal;
    }

  if (r_symndx >= htab->elf.dynsym->dynsymcount)
    {
      return reloc_class_normal;
    }

  const bfd_byte *sym_base = htab->elf.dynsym->contents;
  size_t sym_size = bed->s->sizeof_sym;
  const bfd_byte *sym_ptr = sym_base + (r_symndx * sym_size);

  if (!bed->s->swap_symbol_in (abfd, sym_ptr, 0, &sym))
    {
      return reloc_class_normal;
    }

  if (ELF_ST_TYPE (sym.st_info) == STT_GNU_IFUNC)
    {
      return reloc_class_ifunc;
    }

  switch ((int) ELF32_R_TYPE (rela->r_info))
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
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  bfd *dynobj = htab->elf.dynobj;
  asection *sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (htab->elf.dynamic_sections_created)
    {
      if (sdyn == NULL || htab->elf.sgot == NULL)
        return false; /* Indicate an error instead of aborting. */

      Elf32_External_Dyn *dyncon = (Elf32_External_Dyn *) sdyn->contents;
      Elf32_External_Dyn *dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);

      for (; dyncon < dynconend; ++dyncon)
	{
	  Elf_Internal_Dyn dyn;
	  bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

	  asection *s = NULL;
	  switch (dyn.d_tag)
	    {
	    case DT_PLTGOT:
	      s = htab->elf.sgotplt;
	      if (s && s->output_section)
	        dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	      else
	        return false; /* Handle missing section gracefully */
	      break;

	    case DT_JMPREL:
	      s = htab->elf.srelplt;
	      if (s && s->output_section)
	        dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	      else
	        return false; /* Handle missing section gracefully */
	      break;

	    case DT_PLTRELSZ:
	      if (htab->elf.srelplt)
	        dyn.d_un.d_val = htab->elf.srelplt->size;
	      else
	        return false; /* Handle missing section gracefully */

	      if (htab->elf.irelplt)
		dyn.d_un.d_val += htab->elf.irelplt->size;
	      break;

	    default:
	      continue;
	    }
	  bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
	}

      /* Fill in the special first entry in the procedure linkage table.  */
      if (htab->elf.splt && htab->elf.splt->size > 0 && htab->elf.splt->contents)
	{
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
	      if (htab->elf.sgotplt && htab->elf.sgotplt->output_section)
		{
		  bfd_put_32 (output_bfd,
			      htab->elf.sgotplt->output_section->vma
			      + htab->elf.sgotplt->output_offset,
			      htab->elf.splt->contents + 24);
		}
	      else
		{
		  /* Handle missing sgotplt or output_section gracefully */
		  return false;
		}
	    }
	  if (htab->elf.splt->output_section)
	    elf_section_data (htab->elf.splt->output_section)->this_hdr.sh_entsize = 4;
	  else
	    return false;
	}
    }

  if (htab->elf.sgotplt)
    {
      /* Fill in the first three entries in the global offset table.  */
      if (htab->elf.sgotplt->size > 0 && htab->elf.sgotplt->contents)
	{
	  bfd_vma sdyn_vma_offset = 0;
	  if (sdyn && sdyn->output_section)
	    sdyn_vma_offset = sdyn->output_section->vma + sdyn->output_offset;

	  bfd_put_32 (output_bfd, sdyn_vma_offset, htab->elf.sgotplt->contents);
	  bfd_put_32 (output_bfd, (bfd_vma) 0, htab->elf.sgotplt->contents + 4); /* Shared object struct ptr */
	  bfd_put_32 (output_bfd, (bfd_vma) 0, htab->elf.sgotplt->contents + 8); /* _dl_runtime_resolve */
	}

      if (htab->elf.sgotplt->output_section)
	elf_section_data (htab->elf.sgotplt->output_section)->this_hdr.sh_entsize = 4;
      else
        return false;
    }

  /* Finish dynamic symbol for local IFUNC symbols.  */
  for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (!is_s390_elf (ibfd))
	continue;

      struct plt_entry *local_plt = elf_s390_local_plt (ibfd);
      Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (ibfd);

      if (local_plt != NULL)
	{
	  for (unsigned int i = 0; i < symtab_hdr->sh_info; ++i)
	    {
	      if (local_plt[i].plt.offset != (bfd_vma) -1)
		{
		  asection *sec = local_plt[i].sec;
		  if (!sec || !sec->output_section)
		    return false; /* Ensure section and output_section exist */

		  Elf_Internal_Sym *isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, ibfd, i);
		  if (isym == NULL)
		    return false;

		  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
		    {
		      if (!elf_s390_finish_ifunc_symbol (output_bfd, info, NULL, htab,
							 local_plt[i].plt.offset,
							 isym->st_value
							 + sec->output_section->vma
							 + sec->output_offset))
			return false; /* Propagate error from helper function */
		    }
		}
	    }
	}
    }
  return true;
}

/* Support for core dump NOTE sections.  */

static const unsigned int ELF_S390_PRSTATUS_DESCSZ = 224;
static const unsigned int ELF_S390_PR_CURSIG_OFFSET = 12;
static const unsigned int ELF_S390_PR_PID_OFFSET = 24;
static const unsigned int ELF_S390_PR_REG_OFFSET = 72;
static const unsigned int ELF_S390_PR_REG_SIZE = 144;

static bool
elf_s390_grok_prstatus (bfd * abfd, Elf_Internal_Note * note)
{
  if (abfd == NULL || note == NULL || note->descdata == NULL)
    {
      return false;
    }

  if (note->descsz != ELF_S390_PRSTATUS_DESCSZ)
    {
      return false;
    }

  if (note->descsz < (ELF_S390_PR_PID_OFFSET + sizeof(uint32_t)))
    {
      return false;
    }

  elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + ELF_S390_PR_CURSIG_OFFSET);
  elf_tdata (abfd)->core->lwpid = bfd_get_32 (abfd, note->descdata + ELF_S390_PR_PID_OFFSET);

  return _bfd_elfcore_make_pseudosection (abfd, ".reg",
                                          ELF_S390_PR_REG_SIZE,
                                          note->descpos + ELF_S390_PR_REG_OFFSET);
}

#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#define PRPSINFO_S390_SIZE          124U
#define PRPSINFO_S390_PID_OFFSET    12U
#define PRPSINFO_S390_FNAME_OFFSET  28U
#define PRPSINFO_S390_FNAME_LEN     16U
#define PRPSINFO_S390_PSARGS_OFFSET 44U
#define PRPSINFO_S390_PSARGS_LEN    80U

static bool
elf_s390_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  struct elf_core_info *core_info;
  const unsigned char *descdata;

  if (abfd == NULL || note == NULL || note->descdata == NULL)
    {
      return false;
    }

  core_info = elf_tdata (abfd)->core;
  if (core_info == NULL)
    {
      return false;
    }

  descdata = (const unsigned char *)note->descdata;

  switch (note->descsz)
    {
    default:
      return false;

    case PRPSINFO_S390_SIZE:
      core_info->pid = bfd_get_32 (abfd, descdata + PRPSINFO_S390_PID_OFFSET);

      core_info->program = _bfd_elfcore_strndup (
          abfd, descdata + PRPSINFO_S390_FNAME_OFFSET, PRPSINFO_S390_FNAME_LEN);
      if (core_info->program == NULL)
        {
          return false;
        }

      core_info->command = _bfd_elfcore_strndup (
          abfd, descdata + PRPSINFO_S390_PSARGS_OFFSET, PRPSINFO_S390_PSARGS_LEN);
      if (core_info->command == NULL)
        {
          return false;
        }
      break;
    }

  if (core_info->command != NULL)
    {
      size_t len = strlen (core_info->command);
      if (len > 0 && core_info->command[len - 1] == ' ')
        {
          core_info->command[len - 1] = '\0';
        }
    }

  return true;
}

static char *
elf_s390_write_core_note (bfd *abfd, char *buf, int *bufsiz,
			  int note_type, ...)
{
  va_list ap;

  switch (note_type)
    {
    default:
      return NULL;

    case NT_PRPSINFO:
      {
	char data[124] = { 0 }; /* Zero-initialize the entire buffer */
	const char *fname, *psargs;
        size_t fname_len, psargs_len;

	va_start (ap, note_type);
	fname = va_arg (ap, const char *);
	psargs = va_arg (ap, const char *);
	va_end (ap);

        /* Copy fname into the 16-byte field at offset 28.
         * The field is part of a zero-initialized buffer,
         * so if fname is shorter than 16, the remaining bytes
         * of the field will be implicitly null-padded.
         * If fname is longer, it will be truncated to 16 bytes.
         * This matches the behavior of strncpy for fixed-size fields. */
        fname_len = strlen(fname);
        memcpy(data + 28, fname, (fname_len < 16) ? fname_len : 16);

        /* Copy psargs into the 80-byte field at offset 44.
         * Similar behavior to fname for padding and truncation. */
        psargs_len = strlen(psargs);
        memcpy(data + 44, psargs, (psargs_len < 80) ? psargs_len : 80);

	return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				   &data, sizeof (data));
      }

    case NT_PRSTATUS:
      {
	char data[224] = { 0 }; /* Initialize buffer to zeros */
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
	memcpy (data + 72, gregs, 144);
	return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				   &data, sizeof (data));
      }
    }
  /* NOTREACHED */
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
elf_s390_plt_sym_val (bfd_vma i, const asection *plt,
		      const arelent *rel ATTRIBUTE_UNUSED)
{
  if (plt == NULL)
    {
      /* Handle null pointer for 'plt'. Returning 0 (BFD_VMA_ZERO) is a
         common way to indicate an invalid or error address for bfd_vma. */
      return (bfd_vma) 0;
    }

  return plt->vma + PLT_FIRST_ENTRY_SIZE + i * PLT_ENTRY_SIZE;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
elf32_s390_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;

  if (!is_s390_elf (ibfd) || !is_s390_elf (obfd))
    return true;

  if (!elf_s390_merge_obj_attributes (ibfd, info))
    return false;

  Elf_Internal_Ehdr *const obfd_ehdr = elf_elfheader (obfd);
  const Elf_Internal_Ehdr *const ibfd_ehdr = elf_elfheader (ibfd);

  obfd_ehdr->e_flags |= ibfd_ehdr->e_flags;

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
