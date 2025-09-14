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
elf_s390_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                            bfd_reloc_code_real_type code)
{
  typedef struct
  {
    bfd_reloc_code_real_type code;
    reloc_howto_type *howto;
  } code_map_t;

  static const code_map_t map[] =
  {
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

  unsigned int i;
  for (i = 0; i < (unsigned int)(sizeof(map) / sizeof(map[0])); ++i)
    if (map[i].code == code)
      return map[i].howto;

  return NULL;
}

static reloc_howto_type *
elf_s390_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  size_t i;
  size_t count;
  reloc_howto_type *howto;
  reloc_howto_type *extras[2];
  const char *name;

  if (r_name == NULL)
    return NULL;

  count = sizeof (elf_howto_table) / sizeof (elf_howto_table[0]);

  for (i = 0; i < count; i++)
    {
      howto = &elf_howto_table[i];
      name = howto->name;
      if (name != NULL && strcasecmp (name, r_name) == 0)
        return howto;
    }

  extras[0] = &elf32_s390_vtinherit_howto;
  extras[1] = &elf32_s390_vtentry_howto;

  for (i = 0; i < sizeof (extras) / sizeof (extras[0]); i++)
    {
      name = extras[i]->name;
      if (name != NULL && strcasecmp (name, r_name) == 0)
        return extras[i];
    }

  return NULL;
}

/* We need to use ELF32_R_TYPE so we have our own copy of this function,
   and elf32-s390.c has its own copy.  */

static bool
elf_s390_info_to_howto (bfd *abfd,
			arelent *cache_ptr,
			Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE (dst->r_info);
  const unsigned int howto_count = (unsigned int) (sizeof (elf_howto_table) / sizeof (elf_howto_table[0]));
  const reloc_howto_type *howto;

  switch (r_type)
    {
    case R_390_GNU_VTINHERIT:
      howto = &elf32_s390_vtinherit_howto;
      break;

    case R_390_GNU_VTENTRY:
      howto = &elf32_s390_vtentry_howto;
      break;

    default:
      if (r_type >= howto_count)
	{
	  _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			      abfd, r_type);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      howto = &elf_howto_table[r_type];
      break;
    }

  cache_ptr->howto = howto;
  return true;
}

/* A relocation function which doesn't do anything.  */
static bfd_reloc_status_type
s390_tls_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                arelent *reloc_entry,
                asymbol *symbol ATTRIBUTE_UNUSED,
                void *data ATTRIBUTE_UNUSED,
                asection *input_section,
                bfd *output_bfd,
                char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd != NULL && reloc_entry != NULL && input_section != NULL)
    {
      reloc_entry->address += input_section->output_offset;
    }
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

  if (output_bfd != NULL)
    {
      if ((symbol->flags & BSF_SECTION_SYM) == 0
	  && (!howto->partial_inplace || reloc_entry->addend == 0))
	{
	  reloc_entry->address += input_section->output_offset;
	  return bfd_reloc_ok;
	}
      return bfd_reloc_continue;
    }

  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;

  const asection *sym_sec = symbol->section;
  const asection *out_sym_sec = sym_sec->output_section;
  const asection *out_in_sec = input_section->output_section;

  bfd_vma relocation = symbol->value
		       + out_sym_sec->vma
		       + sym_sec->output_offset
		       + reloc_entry->addend;

  if (howto->pc_relative)
    {
      relocation -= out_in_sec->vma + input_section->output_offset;
      relocation -= reloc_entry->address;
    }

  bfd_byte *location = (bfd_byte *) data + reloc_entry->address;
  bfd_vma insn = bfd_get_32 (abfd, location);
  insn |= ((relocation & 0xFFF) << 16) | ((relocation & 0xFF000) >> 4);
  bfd_put_32 (abfd, insn, location);

  if ((bfd_signed_vma) relocation < -0x80000
      || (bfd_signed_vma) relocation > 0x7ffff)
    return bfd_reloc_overflow;

  return bfd_reloc_ok;
}

static bool
elf_s390_is_local_label_name(bfd *abfd, const char *name)
{
  if (name != NULL)
    {
      const char c0 = name[0];
      if (c0 == '.')
        {
          const char c1 = name[1];
          if (c1 == 'X' || c1 == 'L')
            return true;
        }
    }

  if (abfd == NULL || name == NULL)
    return false;

  return _bfd_elf_is_local_label_name(abfd, name);
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
  if (abfd == NULL)
    return false;

  const size_t tdata_size = sizeof (struct elf_s390_obj_tdata);
  return bfd_elf_allocate_object (abfd, tdata_size) != 0;
}

static bool
elf_s390_object_p(bfd *abfd)
{
  if (abfd == NULL)
    return false;
  return bfd_default_set_arch_mach(abfd, bfd_arch_s390, bfd_mach_s390_31) != 0;
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
link_hash_newfunc(struct bfd_hash_entry *entry,
                  struct bfd_hash_table *table,
                  const char *string)
{
  if (entry == NULL)
    {
      if (table == NULL)
        return NULL;

      entry = bfd_hash_allocate(table, sizeof(struct elf_s390_link_hash_entry));
      if (entry == NULL)
        return NULL;
    }

  entry = _bfd_elf_link_hash_newfunc(entry, table, string);
  if (entry == NULL)
    return NULL;

  {
    struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry *) entry;
    eh->gotplt_refcount = 0;
    eh->tls_type = GOT_UNKNOWN;
    eh->ifunc_resolver_address = 0;
    eh->ifunc_resolver_section = NULL;
  }

  return entry;
}

/* Create an s390 ELF linker hash table.  */

static struct bfd_link_hash_table *
elf_s390_link_hash_table_create(bfd *abfd)
{
  struct elf_s390_link_hash_table *table;

  if (abfd == NULL)
    return NULL;

  table = bfd_zmalloc(sizeof *table);
  if (table == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init(&table->elf, abfd, link_hash_newfunc,
                                     sizeof(struct elf_s390_link_hash_entry)))
    {
      free(table);
      return NULL;
    }

  return &table->elf.root;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
elf_s390_copy_indirect_symbol (struct bfd_link_info *info,
                               struct elf_link_hash_entry *dir,
                               struct elf_link_hash_entry *ind)
{
  const int is_indirect = (ind->root.type == bfd_link_hash_indirect);

  if (is_indirect && dir->got.refcount <= 0)
    {
      struct elf_s390_link_hash_entry *edir =
        (struct elf_s390_link_hash_entry *) dir;
      struct elf_s390_link_hash_entry *eind =
        (struct elf_s390_link_hash_entry *) ind;

      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
    }

  if (ELIMINATE_COPY_RELOCS && !is_indirect && dir->dynamic_adjusted)
    {
      if (dir->versioned != versioned_hidden)
        {
          dir->ref_dynamic |= ind->ref_dynamic;
        }
      dir->ref_regular |= ind->ref_regular;
      dir->ref_regular_nonweak |= ind->ref_regular_nonweak;
      dir->needs_plt |= ind->needs_plt;
      return;
    }

  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

static int
elf_s390_tls_transition(struct bfd_link_info *info, int r_type, int is_local)
{
  if (info && bfd_link_pic(info))
    return r_type;

  switch (r_type)
    {
    case R_390_TLS_LDM32:
      return R_390_TLS_LE32;

    case R_390_TLS_GD32:
    case R_390_TLS_IE32:
      return is_local ? R_390_TLS_LE32 : R_390_TLS_IE32;

    case R_390_TLS_GOTIE32:
      return is_local ? R_390_TLS_LE32 : R_390_TLS_GOTIE32;

    default:
      return r_type;
    }
}

/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bool
elf_s390_check_relocs (bfd *abfd,
                       struct bfd_link_info *info,
                       asection *sec,
                       const Elf_Internal_Rela *relocs)
{
  struct elf_s390_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sreloc = NULL;
  bfd_signed_vma *local_got_refcounts;
  int tls_type, old_tls_type;
  Elf_Internal_Sym *isym = NULL;

  if (bfd_link_relocatable (info))
    return true;

  BFD_ASSERT (is_s390_elf (abfd));

  htab = elf_s390_hash_table (info);
  symtab_hdr = &elf_symtab_hdr (abfd);
  sym_hashes = elf_sym_hashes (abfd);
  local_got_refcounts = elf_local_got_refcounts (abfd);

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      unsigned int r_type;
      unsigned int r_symndx;
      unsigned int orig_type;
      bool is_pc_reloc;
      struct elf_link_hash_entry *h;

      r_symndx = ELF32_R_SYM (rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
        {
          _bfd_error_handler (_("%pB: bad symbol index: %d"),
                              abfd, r_symndx);
          return false;
        }

      if (r_symndx < symtab_hdr->sh_info)
        {
          isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd, r_symndx);
          if (isym == NULL)
            return false;

          if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
            {
              struct plt_entry *plt;

              if (htab->elf.dynobj == NULL)
                htab->elf.dynobj = abfd;

              if (!s390_elf_create_ifunc_sections (htab->elf.dynobj, info))
                return false;

              if (local_got_refcounts == NULL)
                {
                  if (!elf_s390_allocate_local_syminfo (abfd, symtab_hdr))
                    return false;
                  local_got_refcounts = elf_local_got_refcounts (abfd);
                }
              plt = elf_s390_local_plt (abfd);
              plt[r_symndx].plt.refcount++;
            }
          h = NULL;
        }
      else
        {
          h = sym_hashes[r_symndx - symtab_hdr->sh_info];
          while (h->root.type == bfd_link_hash_indirect
                 || h->root.type == bfd_link_hash_warning)
            h = (struct elf_link_hash_entry *) h->root.u.i.link;
        }

      orig_type = ELF32_R_TYPE (rel->r_info);
      r_type = elf_s390_tls_transition (info, orig_type, h == NULL);

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
          if (h == NULL && local_got_refcounts == NULL)
            {
              if (!elf_s390_allocate_local_syminfo (abfd, symtab_hdr))
                return false;
              local_got_refcounts = elf_local_got_refcounts (abfd);
            }
        case R_390_GOTOFF16:
        case R_390_GOTOFF32:
        case R_390_GOTPC:
        case R_390_GOTPCDBL:
          if (htab->elf.sgot == NULL)
            {
              if (htab->elf.dynobj == NULL)
                htab->elf.dynobj = abfd;
              if (!_bfd_elf_create_got_section (htab->elf.dynobj, info))
                return false;
            }
        }

      if (h != NULL)
        {
          if (htab->elf.dynobj == NULL)
            htab->elf.dynobj = abfd;
          if (!s390_elf_create_ifunc_sections (htab->elf.dynobj, info))
            return false;

          if (s390_is_ifunc_symbol_p (h) && h->def_regular)
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
          if (h == NULL || !s390_is_ifunc_symbol_p (h) || !h->def_regular)
            break;
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
          if (bfd_link_pic (info))
            info->flags |= DF_STATIC_TLS;
        case R_390_GOT12:
        case R_390_GOT16:
        case R_390_GOT20:
        case R_390_GOT32:
        case R_390_GOTENT:
        case R_390_TLS_GD32:
          switch (r_type)
            {
            default:
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
            }

          if (h != NULL)
            {
              h->got.refcount += 1;
              old_tls_type = elf_s390_hash_entry (h)->tls_type;
            }
          else
            {
              local_got_refcounts[r_symndx] += 1;
              old_tls_type = elf_s390_local_got_tls_type (abfd)[r_symndx];
            }

          if (old_tls_type != tls_type && old_tls_type != GOT_UNKNOWN)
            {
              if (old_tls_type == GOT_NORMAL || tls_type == GOT_NORMAL)
                {
                  const char *name = NULL;
                  if (h != NULL)
                    name = h->root.root.string;
                  else
                    {
                      isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd, r_symndx);
                      if (isym != NULL)
                        name = bfd_elf_sym_name (abfd, symtab_hdr, isym, NULL);
                    }
                  if (name == NULL)
                    name = "<?>";
                  _bfd_error_handler (_("%pB: `%s' accessed both as normal and thread local symbol"),
                                      abfd, name);
                  return false;
                }
              if (old_tls_type > tls_type)
                tls_type = old_tls_type;
            }

          if (old_tls_type != tls_type)
            {
              if (h != NULL)
                elf_s390_hash_entry (h)->tls_type = tls_type;
              else
                elf_s390_local_got_tls_type (abfd)[r_symndx] = tls_type;
            }

          if (r_type != R_390_TLS_IE32)
            break;
        case R_390_TLS_LE32:
          if (r_type == R_390_TLS_LE32 && bfd_link_pie (info))
            break;

          if (!bfd_link_pic (info))
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
          if (h != NULL && bfd_link_executable (info))
            {
              h->non_got_ref = 1;

              if (!bfd_link_pic (info))
                {
                  h->plt.refcount += 1;
                }
            }

          is_pc_reloc = (orig_type == R_390_PC16
                         || orig_type == R_390_PC12DBL
                         || orig_type == R_390_PC16DBL
                         || orig_type == R_390_PC24DBL
                         || orig_type == R_390_PC32DBL
                         || orig_type == R_390_PC32);

          if ((bfd_link_pic (info)
               && (sec->flags & SEC_ALLOC) != 0
               && (!is_pc_reloc
                   || (h != NULL
                       && (! SYMBOLIC_BIND (info, h)
                           || h->root.type == bfd_link_hash_defweak
                           || !h->def_regular))))
              || (ELIMINATE_COPY_RELOCS
                  && !bfd_link_pic (info)
                  && (sec->flags & SEC_ALLOC) != 0
                  && h != NULL
                  && (h->root.type == bfd_link_hash_defweak
                      || !h->def_regular)))
            {
              struct elf_dyn_relocs *p;
              struct elf_dyn_relocs **head;

              if (sreloc == NULL)
                {
                  if (htab->elf.dynobj == NULL)
                    htab->elf.dynobj = abfd;

                  sreloc = _bfd_elf_make_dynamic_reloc_section
                    (sec, htab->elf.dynobj, 2, abfd, true);

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

                  isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, abfd, r_symndx);
                  if (isym == NULL)
                    return false;

                  s = bfd_section_from_elf_index (abfd, isym->st_shndx);
                  if (s == NULL)
                    s = sec;

                  vpp = &elf_section_data (s)->local_dynrel;
                  head = (struct elf_dyn_relocs **) vpp;
                }

              p = *head;
              if (p == NULL || p->sec != sec)
                {
                  size_t amt = sizeof *p;

                  p = (struct elf_dyn_relocs *) bfd_alloc (htab->elf.dynobj, amt);
                  if (p == NULL)
                    return false;
                  p->next = *head;
                  *head = p;
                  p->sec = sec;
                  p->count = 0;
                  p->pc_count = 0;
                }

              p->count += 1;
              if (is_pc_reloc)
                p->pc_count += 1;
            }
          break;

        case R_390_GNU_VTINHERIT:
          if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
            return false;
          break;

        case R_390_GNU_VTENTRY:
          if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
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
elf_s390_gc_mark_hook(asection *sec,
                      struct bfd_link_info *info,
                      Elf_Internal_Rela *rel,
                      struct elf_link_hash_entry *h,
                      Elf_Internal_Sym *sym)
{
  if (h != NULL && rel != NULL)
    {
      unsigned int rtype = ELF32_R_TYPE(rel->r_info);
      if (rtype == R_390_GNU_VTINHERIT || rtype == R_390_GNU_VTENTRY)
        return NULL;
    }

  return _bfd_elf_gc_mark_hook(sec, info, rel, h, sym);
}

/* Make sure we emit a GOT entry if the symbol was supposed to have a PLT
   entry but we found we will not create any.  Called when we find we will
   not have any PLT for this symbol, by for example
   elf_s390_adjust_dynamic_symbol when we're doing a proper dynamic link,
   or elf_s390_late_size_sections if no dynamic sections will be
   created (we're only linking static objects).  */

static void
elf_s390_adjust_gotplt(struct elf_s390_link_hash_entry *h)
{
  if (h == NULL)
    return;

  struct elf_s390_link_hash_entry *entry = h;

  if (entry->elf.root.type == bfd_link_hash_warning) {
    if (entry->elf.root.u.i.link == NULL)
      return;
    entry = (struct elf_s390_link_hash_entry *) entry->elf.root.u.i.link;
  }

  if (entry->gotplt_refcount <= 0)
    return;

  entry->elf.got.refcount += entry->gotplt_refcount;
  entry->gotplt_refcount = -1;
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
  asection *s = NULL, *srel = NULL;

  if (s390_is_ifunc_symbol_p (h))
    {
      if (h->ref_regular && SYMBOL_CALLS_LOCAL (info, h))
	{
	  bfd_size_type pc_count = 0, count = 0;
	  struct elf_dyn_relocs **pp = &h->dyn_relocs;
	  struct elf_dyn_relocs *p;

	  while ((p = *pp) != NULL)
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
		++h->plt.refcount;
	    }
	}

      if (h->plt.refcount <= 0)
	{
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}
      return true;
    }

  if (h->type == STT_FUNC || h->needs_plt)
    {
      if (h->plt.refcount <= 0
	  || SYMBOL_CALLS_LOCAL (info, h)
	  || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	{
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	  elf_s390_adjust_gotplt ((struct elf_s390_link_hash_entry *) h);
	}
      return true;
    }

  h->plt.offset = (bfd_vma) -1;

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
      srel->size += (bfd_size_type) sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bool
allocate_dynrelocs(struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct elf_s390_link_hash_table *htab;
  struct elf_dyn_relocs *p;
  struct elf_s390_link_hash_entry *hs;
  bool pic, dyn;

  if (h == NULL || inf == NULL)
    return false;

  info = (struct bfd_link_info *) inf;
  htab = elf_s390_hash_table(info);
  if (htab == NULL)
    return false;

  if (h->root.type == bfd_link_hash_indirect)
    return true;

  pic = bfd_link_pic(info);
  dyn = htab->elf.dynamic_sections_created;
  hs = elf_s390_hash_entry(h);

  if (s390_is_ifunc_symbol_p(h) && h->def_regular)
    return s390_elf_allocate_ifunc_dyn_relocs(info, h);

  if (dyn && h->plt.refcount > 0)
    {
      if (h->dynindx == -1 && !h->forced_local)
        {
          if (!bfd_elf_link_record_dynamic_symbol(info, h))
            return false;
        }

      if (pic || WILL_CALL_FINISH_DYNAMIC_SYMBOL(1, 0, h))
        {
          asection *s = htab->elf.splt;
          if (s == NULL || htab->elf.sgotplt == NULL || htab->elf.srelplt == NULL)
            return false;

          if (s->size == 0)
            s->size += PLT_FIRST_ENTRY_SIZE;

          h->plt.offset = s->size;

          if (!pic && !h->def_regular)
            {
              h->root.u.def.section = s;
              h->root.u.def.value = h->plt.offset;
            }

          s->size += PLT_ENTRY_SIZE;
          htab->elf.sgotplt->size += GOT_ENTRY_SIZE;
          htab->elf.srelplt->size += sizeof(Elf32_External_Rela);
        }
      else
        {
          h->plt.offset = (bfd_vma) -1;
          h->needs_plt = 0;
          elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *) h);
        }
    }
  else
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
      elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *) h);
    }

  if (h->got.refcount > 0 && !pic && h->dynindx == -1 && hs->tls_type >= GOT_TLS_IE)
    {
      if (hs->tls_type == GOT_TLS_IE_NLT)
        {
          if (htab->elf.sgot == NULL)
            return false;
          h->got.offset = htab->elf.sgot->size;
          htab->elf.sgot->size += GOT_ENTRY_SIZE;
        }
      else
        {
          h->got.offset = (bfd_vma) -1;
        }
    }
  else if (h->got.refcount > 0)
    {
      asection *sgot = htab->elf.sgot;
      asection *srelgot = htab->elf.srelgot;
      int tls_type = hs->tls_type;

      if (sgot == NULL)
        return false;

      if (h->dynindx == -1 && !h->forced_local)
        {
          if (!bfd_elf_link_record_dynamic_symbol(info, h))
            return false;
        }

      h->got.offset = sgot->size;
      sgot->size += GOT_ENTRY_SIZE;
      if (tls_type == GOT_TLS_GD)
        sgot->size += GOT_ENTRY_SIZE;

      if ((tls_type == GOT_TLS_GD && h->dynindx == -1) || tls_type >= GOT_TLS_IE)
        {
          if (srelgot == NULL)
            return false;
          srelgot->size += sizeof(Elf32_External_Rela);
        }
      else if (tls_type == GOT_TLS_GD)
        {
          if (srelgot == NULL)
            return false;
          srelgot->size += 2 * sizeof(Elf32_External_Rela);
        }
      else if (!UNDEFWEAK_NO_DYNAMIC_RELOC(info, h) && (pic || WILL_CALL_FINISH_DYNAMIC_SYMBOL(dyn, 0, h)))
        {
          if (srelgot == NULL)
            return false;
          srelgot->size += sizeof(Elf32_External_Rela);
        }
    }
  else
    {
      h->got.offset = (bfd_vma) -1;
    }

  if (h->dyn_relocs == NULL)
    return true;

  if (pic)
    {
      if (SYMBOL_CALLS_LOCAL(info, h))
        {
          struct elf_dyn_relocs **pp;
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
          if (ELF_ST_VISIBILITY(h->other) != STV_DEFAULT || UNDEFWEAK_NO_DYNAMIC_RELOC(info, h))
            {
              h->dyn_relocs = NULL;
            }
          else if (h->dynindx == -1 && !h->forced_local)
            {
              if (!bfd_elf_link_record_dynamic_symbol(info, h))
                return false;
            }
        }
    }
  else if (ELIMINATE_COPY_RELOCS)
    {
      bool need_copy = false;
      if (!h->non_got_ref && ((h->def_dynamic && !h->def_regular) || (dyn && (h->root.type == bfd_link_hash_undefweak || h->root.type == bfd_link_hash_undefined))))
        {
          if (h->dynindx == -1 && !h->forced_local)
            {
              if (!bfd_elf_link_record_dynamic_symbol(info, h))
                return false;
            }
          if (h->dynindx != -1)
            need_copy = true;
        }

      if (!need_copy)
        h->dyn_relocs = NULL;
    }

  for (p = h->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data(p->sec)->sreloc;
      if (sreloc == NULL)
        return false;
      sreloc->size += p->count * sizeof(Elf32_External_Rela);
    }

  return true;
}

/* Set the sizes of the dynamic sections.  */

static bool
elf_s390_late_size_sections (bfd *output_bfd ATTRIBUTE_UNUSED,
			     struct bfd_link_info *info)
{
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  bfd *dynobj;
  asection *s;
  bool relocs = false;
  bfd *ibfd;

  if (htab == NULL)
    return false;

  dynobj = htab->elf.dynobj;
  if (dynobj == NULL)
    return true;

  if (htab->elf.dynamic_sections_created
      && bfd_link_executable (info) && !info->nointerp)
    {
      s = bfd_get_linker_section (dynobj, ".interp");
      if (s == NULL)
	abort ();
      s->size = sizeof ELF_DYNAMIC_INTERPRETER;
      s->contents = (unsigned char *) ELF_DYNAMIC_INTERPRETER;
      s->alloced = 1;
    }

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (!is_s390_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = elf_section_data (s)->local_dynrel; p != NULL; p = p->next)
	    {
	      if (!bfd_is_abs_section (p->sec)
		  && bfd_is_abs_section (p->sec->output_section))
		continue;

	      if (p->count != 0)
		{
		  asection *srela = elf_section_data (p->sec)->sreloc;
		  srela->size += p->count * sizeof (Elf32_External_Rela);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      bfd_signed_vma *local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
	continue;

      Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (ibfd);
      bfd_size_type locsymcount = symtab_hdr->sh_info;
      bfd_signed_vma *end_local_got = local_got + locsymcount;
      char *local_tls_type = elf_s390_local_got_tls_type (ibfd);
      asection *sgot = htab->elf.sgot;
      asection *srelgot = htab->elf.srelgot;

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

      struct plt_entry *local_plt = elf_s390_local_plt (ibfd);
      if (local_plt != NULL)
	{
	  bfd_size_type i;
	  for (i = 0; i < locsymcount; i++)
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

  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      bool is_known =
	(s == htab->elf.splt
	 || s == htab->elf.sgot
	 || s == htab->elf.sgotplt
	 || s == htab->elf.sdynbss
	 || s == htab->elf.sdynrelro
	 || s == htab->elf.iplt
	 || s == htab->elf.igotplt
	 || s == htab->irelifunc);

      bool is_rela = startswith (bfd_section_name (s), ".rela");

      if (!is_known && !is_rela)
	continue;

      if (is_rela)
	{
	  if (s->size != 0)
	    relocs = true;
	  s->reloc_count = 0;
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
dtpoff_base(struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab;

  if (info == NULL)
    return 0;

  htab = elf_hash_table(info);
  if (htab == NULL || htab->tls_sec == NULL)
    return 0;

  return htab->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
tpoff (struct bfd_link_info *info, bfd_vma address)
{
  struct elf_link_hash_table *htab;
  bfd_vma tls_size;
  bfd_vma sec_vma;

  if (info == NULL)
    return 0;

  htab = elf_hash_table (info);
  if (htab == NULL || htab->tls_sec == NULL)
    return 0;

  tls_size = htab->tls_size;
  sec_vma = htab->tls_sec->vma;

  return (tls_size + sec_vma) - address;
}

/* Complain if TLS instruction relocation is against an invalid
   instruction.  */

static void
invalid_tls_insn (bfd *input_bfd,
                  asection *input_section,
                  Elf_Internal_Rela *rel)
{
  const reloc_howto_type *howto = NULL;
  const char *howto_name = "unknown";
  uint64_t offset = 0;

  if (rel == NULL)
    {
      _bfd_error_handler (_("%pB(%pA+%#" PRIx64 "): invalid instruction for TLS relocation %s"),
                          input_bfd, input_section, (uint64_t) 0, howto_name);
      bfd_set_error (bfd_error_bad_value);
      return;
    }

  offset = (uint64_t) rel->r_offset;
  howto = elf_howto_table + ELF32_R_TYPE (rel->r_info);
  if (howto != NULL && howto->name != NULL)
    howto_name = howto->name;

  _bfd_error_handler (_("%pB(%pA+%#" PRIx64 "): invalid instruction for TLS relocation %s"),
                      input_bfd, input_section, offset, howto_name);
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
		  bfd_put_32 (output_bfd, relocation,
			      htab->elf.sgot->contents +
			      local_got_offsets[r_symndx]);
		  relocation = (local_got_offsets[r_symndx]
				+ htab->elf.sgot->output_offset);
		  if (r_type == R_390_GOTENT || r_type == R_390_GOTPLTENT)
		    relocation += htab->elf.sgot->output_section->vma;
		  break;
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
		  plt_index = h->plt.offset / PLT_ENTRY_SIZE;
		  relocation = (plt_index * GOT_ENTRY_SIZE +
				htab->elf.igotplt->output_offset);
		  if (r_type == R_390_GOTPLTENT)
		    relocation += htab->elf.igotplt->output_section->vma;
		}
	      else
		{
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
	    abort ();

	  if (h != NULL)
	    {
	      bool dyn;

	      off = h->got.offset;
	      dyn = htab->elf.dynamic_sections_created;

	      if (s390_is_ifunc_symbol_p (h))
		{
		  BFD_ASSERT (h->plt.offset != (bfd_vma) -1);
		  if (off == (bfd_vma)-1)
		    {
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
		abort ();

	      off = local_got_offsets[r_symndx];

	      if ((off & 1) != 0)
		off &= ~1;
	      else
		{
		  bfd_put_32 (output_bfd, relocation,
			      htab->elf.sgot->contents + off);

		  if (bfd_link_pic (info))
		    {
		      asection *srelgot;
		      Elf_Internal_Rela outrel;
		      bfd_byte *loc;

		      srelgot = htab->elf.srelgot;
		      if (srelgot == NULL)
			abort ();

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
	    abort ();

	  relocation = base_got->output_offset + off;

	  if (r_type == R_390_GOTENT
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
	      relocation = (htab->elf.iplt->output_section->vma
			    + htab->elf.iplt->output_offset
			    + h->plt.offset
			    - htab->elf.sgot->output_section->vma);
	      goto do_relocation;
	    }

	  relocation -= htab->elf.sgot->output_section->vma;
	  break;

	case R_390_GOTPC:
	case R_390_GOTPCDBL:
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
	    relocation = (htab->elf.iplt->output_section->vma
			  + htab->elf.iplt->output_offset
			  + h->plt.offset);
	  else
	    relocation = (htab->elf.splt->output_section->vma
			  + htab->elf.splt->output_offset
			  + h->plt.offset);
	  unresolved_reloc = false;
	  break;

	case R_390_PLTOFF16:
	case R_390_PLTOFF32:
	  if (h == NULL
	      || h->plt.offset == (bfd_vma) -1
	      || (htab->elf.splt == NULL && !s390_is_ifunc_symbol_p (h)))
	    {
	      relocation -= htab->elf.sgot->output_section->vma;
	      break;
	    }

	  if (s390_is_ifunc_symbol_p (h))
	    relocation = (htab->elf.iplt->output_section->vma
			  + htab->elf.iplt->output_offset
			  + h->plt.offset
			  - htab->elf.sgot->output_section->vma);
	  else
	    relocation = (htab->elf.splt->output_section->vma
			  + htab->elf.splt->output_offset
			  + h->plt.offset
			  - htab->elf.sgot->output_section->vma);
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
		    abort ();

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
			      sindx = elf_section_data (osec)->dynindx;
			    }
			  BFD_ASSERT (sindx != 0);

			  outrel.r_addend -= osec->vma;
			}
		      outrel.r_info = ELF32_R_INFO (sindx, r_type);
		    }
		}

	      sreloc = elf_section_data (input_section)->sreloc;
	      if (sreloc == NULL)
		abort ();

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
		abort ();
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
	      BFD_ASSERT (! unresolved_reloc);
	      bfd_put_32 (output_bfd, -tpoff (info, relocation) + rel->r_addend,
			  contents + rel->r_offset);
	      continue;
	    }

	  if (htab->elf.sgot == NULL)
	    abort ();

	  if (h != NULL)
	    off = h->got.offset;
	  else
	    {
	      if (local_got_offsets == NULL)
		abort ();

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
		abort ();

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
		      BFD_ASSERT (! unresolved_reloc);
		      bfd_put_32 (output_bfd,
				  relocation - dtpoff_base (info),
				  htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
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
	    abort ();
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
		abort();
	      off = local_got_offsets[r_symndx];
	      if (bfd_link_pic (info))
		goto emit_tls_relocs;
	    }
	  else
	    {
	      off = h->got.offset;
	      tls_type = elf_s390_hash_entry(h)->tls_type;
	      if (bfd_link_pic (info)
		  || h->dynindx != -1
		  || tls_type < GOT_TLS_IE)
		goto emit_tls_relocs;
	    }

	  if (htab->elf.sgot == NULL)
	    abort ();

	  BFD_ASSERT (! unresolved_reloc);
	  bfd_put_32 (output_bfd, -tpoff (info, relocation),
		      htab->elf.sgot->contents + off);
	  relocation = htab->elf.sgot->output_offset + off;
	  if (r_type == R_390_TLS_IEENT)
	    relocation += htab->elf.sgot->output_section->vma;
	  unresolved_reloc = false;
	  break;

	case R_390_TLS_LDM32:
	  if (! bfd_link_pic (info))
	    continue;

	  if (htab->elf.sgot == NULL)
	    abort ();

	  off = htab->tls_ldm_got.offset;
	  if (off & 1)
	    off &= ~1;
	  else
	    {
	      Elf_Internal_Rela outrel;
	      bfd_byte *loc;

	      if (htab->elf.srelgot == NULL)
		abort ();

	      outrel.r_offset = (htab->elf.sgot->output_section->vma
				 + htab->elf.sgot->output_offset + off);

	      bfd_put_32 (output_bfd, 0,
			  htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
	      outrel.r_info = ELF32_R_INFO (0, R_390_TLS_DTPMOD);
	      outrel.r_addend = 0;
	      loc = htab->elf.srelgot->contents;
	      loc += htab->elf.srelgot->reloc_count++
		* sizeof (Elf32_External_Rela);
	      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
	      htab->tls_ldm_got.offset |= 1;
	    }
	  relocation = htab->elf.sgot->output_offset + off;
	  unresolved_reloc = false;
	  break;

	case R_390_TLS_LE32:
	  if (bfd_link_dll (info))
	    {
	      Elf_Internal_Rela outrel;
	      asection *sreloc;
	      bfd_byte *loc;
	      int indx;

	      outrel.r_offset = rel->r_offset
				+ input_section->output_section->vma
				+ input_section->output_offset;
	      if (h != NULL && h->dynindx != -1)
		indx = h->dynindx;
	      else
		indx = 0;
	      outrel.r_info = ELF32_R_INFO (indx, R_390_TLS_TPOFF);
	      if (indx == 0)
		outrel.r_addend = relocation - dtpoff_base (info);
	      else
		outrel.r_addend = 0;
	      sreloc = elf_section_data (input_section)->sreloc;
	      if (sreloc == NULL)
		abort ();
	      loc = sreloc->contents;
	      loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
	      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
	    }
	  else
	    {
	      BFD_ASSERT (! unresolved_reloc);
	      bfd_put_32 (output_bfd, -tpoff (info, relocation) + rel->r_addend,
			  contents + rel->r_offset);
	    }
	  continue;

	case R_390_TLS_LDO32:
	  if (bfd_link_pic (info) || (input_section->flags & SEC_DEBUGGING))
	    relocation -= dtpoff_base (info);
	  else
	    relocation = -tpoff (info, relocation);
	  break;

	case R_390_TLS_LOAD:
	case R_390_TLS_GDCALL:
	case R_390_TLS_LDCALL:
	  tls_type = GOT_UNKNOWN;
	  if (h == NULL && local_got_offsets)
	    tls_type = elf_s390_local_got_tls_type (input_bfd) [r_symndx];
	  else if (h != NULL)
	    tls_type = elf_s390_hash_entry(h)->tls_type;

	  if (tls_type == GOT_TLS_GD)
	    continue;

	  if (r_type == R_390_TLS_LOAD)
	    {
	      if (!bfd_link_pic (info) && (h == NULL || h->dynindx == -1))
		{
		  unsigned int insn, ry;

		  insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
		  if ((insn & 0xff00f000) == 0x58000000)
		    ry = (insn & 0x000f0000);
		  else if ((insn & 0xff0f0000) == 0x58000000)
		    ry = (insn & 0x0000f000) << 4;
		  else if ((insn & 0xff00f000) == 0x5800c000)
		    ry = (insn & 0x000f0000);
		  else if ((insn & 0xff0f0000) == 0x580c0000)
		    ry = (insn & 0x0000f000) << 4;
		  else
		    {
		      invalid_tls_insn (input_bfd, input_section, rel);
		      return false;
		    }
		  insn = 0x18000700 | (insn & 0x00f00000) | ry;
		  bfd_put_32 (output_bfd, insn, contents + rel->r_offset);
		}
	    }
	  else if (r_type == R_390_TLS_GDCALL)
	    {
	      unsigned int insn;

	      insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
	      if ((insn & 0xff000fff) != 0x4d000000 &&
		  (insn & 0xffff0000) != 0xc0e50000 &&
		  (insn & 0xff000000) != 0x0d000000)
		{
		  invalid_tls_insn (input_bfd, input_section, rel);
		  return false;
		}
	      if (!bfd_link_pic (info) && (h == NULL || h->dynindx == -1))
		{
		  if ((insn & 0xff000000) == 0x0d000000)
		    {
		      insn = 0x07070000 | (insn & 0xffff);
		    }
		  else if ((insn & 0xff000000) == 0x4d000000)
		    {
		      insn = 0x47000000;
		    }
		  else
		    {
		      insn = 0xc0040000;
		      bfd_put_16 (output_bfd, 0x0000,
				  contents + rel->r_offset + 4);
		    }
		}
	      else
		{
		  if ((insn & 0xff000000) == 0x0d000000)
		    {
		      invalid_tls_insn (input_bfd, input_section, rel);
		      return false;
		    }

		  if ((insn & 0xff000000) == 0x4d000000)
		    {
		      insn = 0x5822c000;
		    }
		  else
		    {
		      insn = 0x5822c000;
		      bfd_put_16 (output_bfd, 0x0700,
				  contents + rel->r_offset + 4);
		    }
		}
	      bfd_put_32 (output_bfd, insn, contents + rel->r_offset);
	    }
	  else if (r_type == R_390_TLS_LDCALL)
	    {
	      if (!bfd_link_pic (info))
		{
		  unsigned int insn;

		  insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
		  if ((insn & 0xff000fff) != 0x4d000000 &&
		      (insn & 0xffff0000) != 0xc0e50000 &&
		      (insn & 0xff000000) != 0x0d000000)
		    {
		      invalid_tls_insn (input_bfd, input_section, rel);
		      return false;
		    }

		  if ((insn & 0xff000000) == 0x0d000000)
		    {
		      insn = 0x07070000 | (insn & 0xffff);
		    }
		  else if ((insn & 0xff000000) == 0x4d000000)
		    {
		      insn = 0x47000000;
		    }
		  else
		    {
		      insn = 0xc0040000;
		      bfd_put_16 (output_bfd, 0x0000,
				  contents + rel->r_offset + 4);
		    }
		  bfd_put_32 (output_bfd, insn, contents + rel->r_offset);
		}
	    }
	  continue;

	default:
	  break;
	}

      if (unresolved_reloc
	  && !((input_section->flags & SEC_DEBUGGING) != 0
	       && h->def_dynamic)
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      rel->r_offset) != (bfd_vma) -1)
	_bfd_error_handler
	  (_("%pB(%pA+%#" PRIx64 "): "
	     "unresolvable %s relocation against symbol `%s'"),
	   input_bfd,
	   input_section,
	   (uint64_t) rel->r_offset,
	   howto->name,
	   h->root.root.string);

    do_relocation:

      if (r_type == R_390_PC24DBL
	  || r_type == R_390_PLT24DBL)
	rel->r_offset--;

      if (r_type == R_390_20
	  || r_type == R_390_GOT20
	  || r_type == R_390_GOTPLT20
	  || r_type == R_390_TLS_GOTIE20)
	{
	  relocation += rel->r_addend;
	  relocation = (relocation&0xfff) << 8 | (relocation&0xff000) >> 12;
	  r = _bfd_final_link_relocate (howto, input_bfd, input_section,
					contents, rel->r_offset,
					relocation, 0);
	}
      else
	r = _bfd_final_link_relocate (howto, input_bfd, input_section,
				      contents, rel->r_offset,
				      relocation, rel->r_addend);

      if (r != bfd_reloc_ok)
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

	  if (r == bfd_reloc_overflow)
	    (*info->callbacks->reloc_overflow)
	      (info, (h ? &h->root : NULL), name, howto->name,
	       (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	  else
	    {
	      _bfd_error_handler
		(_("%pB(%pA+%#" PRIx64 "): reloc against `%s': error %d"),
		 input_bfd, input_section,
		 (uint64_t) rel->r_offset, name, (int) r);
	      return false;
	    }
	}
    }

  return true;
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
  bfd_byte *loc;
  asection *plt, *gotplt, *relplt;
  bfd_signed_vma relative_offset;
  bfd_vma jump_adjust_value;
  const bfd_byte *entry_template;
  bfd_byte *plt_entry;
  bfd_byte *gotplt_entry;
  bfd_byte *relplt_entry;

  enum
  {
    PLT_JUMP_ADJ_OFF = 20,
    PLT_GOT_FIELD_OFF = 24,
    PLT_RELOC_OFF = 28,
    PLT_GOT_DISP_OFF = 2,
    PLT_GOTPTR_DELTA = 12,
    BRANCH_CONST_ADJ = 18,
    PIC12_MAX = 4096,
    PIC16_MAX = 32768
  };

  if (htab == NULL || htab->elf.iplt == NULL
      || htab->elf.igotplt == NULL
      || htab->elf.irelplt == NULL)
    abort ();

  plt = htab->elf.iplt;
  gotplt = htab->elf.igotplt;
  relplt = htab->elf.irelplt;

  if (plt->contents == NULL || gotplt->contents == NULL || relplt->contents == NULL
      || plt->output_section == NULL || gotplt->output_section == NULL)
    abort ();

  iplt_index = iplt_offset / PLT_ENTRY_SIZE;

  igotiplt_offset = iplt_index * GOT_ENTRY_SIZE;
  got_offset = igotiplt_offset + gotplt->output_offset;

  {
    bfd_signed_vma tmp = (bfd_signed_vma) (plt->output_offset
					   + (PLT_ENTRY_SIZE * iplt_index)
					   + BRANCH_CONST_ADJ);
    relative_offset = -tmp;
    relative_offset /= 2;
  }

  if (relative_offset < -32768)
    {
      bfd_signed_vma adj = - (bfd_signed_vma)
	((((65536 / PLT_ENTRY_SIZE) - 1) * PLT_ENTRY_SIZE) / 2);
      relative_offset = adj;
    }

  jump_adjust_value = ((bfd_vma) relative_offset) << 16;

  if (iplt_offset + PLT_ENTRY_SIZE > plt->size
      || igotiplt_offset + GOT_ENTRY_SIZE > gotplt->size
      || (bfd_size_type) (iplt_index * RELA_ENTRY_SIZE) > relplt->size
      || (relplt->output_offset + (bfd_vma) (iplt_index * RELA_ENTRY_SIZE)) < relplt->output_offset)
    abort ();

  plt_entry = plt->contents + iplt_offset;
  gotplt_entry = gotplt->contents + igotiplt_offset;
  relplt_entry = relplt->contents + iplt_index * RELA_ENTRY_SIZE;

  if (!bfd_link_pic (info))
    {
      entry_template = elf_s390_plt_entry;
      memcpy (plt_entry, entry_template, PLT_ENTRY_SIZE);
      bfd_put_32 (output_bfd, jump_adjust_value, plt_entry + PLT_JUMP_ADJ_OFF);
      bfd_put_32 (output_bfd,
		  (gotplt->output_section->vma + got_offset),
		  plt_entry + PLT_GOT_FIELD_OFF);
    }
  else if (got_offset < PIC12_MAX)
    {
      entry_template = elf_s390_plt_pic12_entry;
      memcpy (plt_entry, entry_template, PLT_ENTRY_SIZE);
      bfd_put_16 (output_bfd, (bfd_vma) 0xc000 | got_offset,
		  plt_entry + PLT_GOT_DISP_OFF);
      bfd_put_32 (output_bfd, jump_adjust_value, plt_entry + PLT_JUMP_ADJ_OFF);
    }
  else if (got_offset < PIC16_MAX)
    {
      entry_template = elf_s390_plt_pic16_entry;
      memcpy (plt_entry, entry_template, PLT_ENTRY_SIZE);
      bfd_put_16 (output_bfd, (bfd_vma) got_offset,
		  plt_entry + PLT_GOT_DISP_OFF);
      bfd_put_32 (output_bfd, jump_adjust_value, plt_entry + PLT_JUMP_ADJ_OFF);
    }
  else
    {
      entry_template = elf_s390_plt_pic_entry;
      memcpy (plt_entry, entry_template, PLT_ENTRY_SIZE);
      bfd_put_32 (output_bfd, jump_adjust_value, plt_entry + PLT_JUMP_ADJ_OFF);
      bfd_put_32 (output_bfd, got_offset, plt_entry + PLT_GOT_FIELD_OFF);
    }

  bfd_put_32 (output_bfd,
	      relplt->output_offset + iplt_index * RELA_ENTRY_SIZE,
	      plt_entry + PLT_RELOC_OFF);

  bfd_put_32 (output_bfd,
	      (plt->output_section->vma
	       + plt->output_offset
	       + iplt_offset
	       + PLT_GOTPTR_DELTA),
	      gotplt_entry);

  rela.r_offset = gotplt->output_section->vma + got_offset;

  if (!h
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

  bfd_elf32_swap_reloca_out (output_bfd, &rela, relplt_entry);
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
  struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry*) h;

  htab = elf_s390_hash_table (info);

  if (h->plt.offset != (bfd_vma) -1)
    {
      asection *splt = htab->elf.splt;
      asection *sgotplt = htab->elf.sgotplt;
      asection *srelplt = htab->elf.srelplt;

      if (s390_is_ifunc_symbol_p (h) && h->def_regular)
	{
	  elf_s390_finish_ifunc_symbol (output_bfd, info, h, htab, h->plt.offset,
					eh->ifunc_resolver_address
					+ eh->ifunc_resolver_section->output_offset
					+ eh->ifunc_resolver_section->output_section->vma);
	}
      else
	{
	  bfd_vma plt_index;
	  bfd_vma got_offset;
	  Elf_Internal_Rela rela;
	  bfd_byte *loc;
	  bfd_byte *plt_entry;
	  bfd_vma relative_offset;
	  const size_t JUMP_ADJ_OFF = 20;
	  const size_t GOT_FIELD_OFF = 24;
	  const size_t RELA_INDEX_OFF = 28;

	  if (h->dynindx == -1 || splt == NULL || sgotplt == NULL || srelplt == NULL)
	    abort ();

	  plt_index = (h->plt.offset - PLT_FIRST_ENTRY_SIZE) / PLT_ENTRY_SIZE;
	  got_offset = (plt_index + 3) * GOT_ENTRY_SIZE;
	  relative_offset = - ((PLT_FIRST_ENTRY_SIZE + (PLT_ENTRY_SIZE * plt_index) + 18) / 2);
	  if (-32768 > (int) relative_offset)
	    relative_offset = -(unsigned) (((65536 / PLT_ENTRY_SIZE - 1) * PLT_ENTRY_SIZE) / 2);

	  plt_entry = splt->contents + h->plt.offset;

	  if (!bfd_link_pic (info))
	    {
	      memcpy (plt_entry, elf_s390_plt_entry, PLT_ENTRY_SIZE);
	      bfd_put_32 (output_bfd,
			  (sgotplt->output_section->vma + sgotplt->output_offset + got_offset),
			  plt_entry + GOT_FIELD_OFF);
	    }
	  else if (got_offset < 4096)
	    {
	      memcpy (plt_entry, elf_s390_plt_pic12_entry, PLT_ENTRY_SIZE);
	      bfd_put_16 (output_bfd, (bfd_vma) 0xc000 | got_offset, plt_entry + 2);
	    }
	  else if (got_offset < 32768)
	    {
	      memcpy (plt_entry, elf_s390_plt_pic16_entry, PLT_ENTRY_SIZE);
	      bfd_put_16 (output_bfd, (bfd_vma) got_offset, plt_entry + 2);
	    }
	  else
	    {
	      memcpy (plt_entry, elf_s390_plt_pic_entry, PLT_ENTRY_SIZE);
	      bfd_put_32 (output_bfd, got_offset, plt_entry + GOT_FIELD_OFF);
	    }

	  bfd_put_32 (output_bfd, (bfd_vma) (relative_offset << 16), plt_entry + JUMP_ADJ_OFF);

	  bfd_put_32 (output_bfd, plt_index * sizeof (Elf32_External_Rela),
		      plt_entry + RELA_INDEX_OFF);

	  bfd_put_32 (output_bfd,
		      (splt->output_section->vma + splt->output_offset + h->plt.offset + 12),
		      sgotplt->contents + got_offset);

	  rela.r_offset = (sgotplt->output_section->vma + sgotplt->output_offset + got_offset);
	  rela.r_info = ELF32_R_INFO (h->dynindx, R_390_JMP_SLOT);
	  rela.r_addend = 0;
	  loc = srelplt->contents + plt_index * sizeof (Elf32_External_Rela);
	  bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);

	  if (!h->def_regular)
	    sym->st_shndx = SHN_UNDEF;
	}
    }

  {
    int tls_type = elf_s390_hash_entry (h)->tls_type;
    if (h->got.offset != (bfd_vma) -1
	&& tls_type != GOT_TLS_GD
	&& tls_type != GOT_TLS_IE
	&& tls_type != GOT_TLS_IE_NLT)
      {
	Elf_Internal_Rela rela;
	bfd_byte *loc;
	asection *sgot = htab->elf.sgot;
	asection *srelgot = htab->elf.srelgot;

	if (sgot == NULL || srelgot == NULL)
	  abort ();

	rela.r_offset = (sgot->output_section->vma
			 + sgot->output_offset
			 + (h->got.offset & ~ (bfd_vma) 1));

	if (h->def_regular && s390_is_ifunc_symbol_p (h))
	  {
	    if (bfd_link_pic (info))
	      {
		goto do_glob_dat;
	      }
	    else
	      {
		bfd_put_32 (output_bfd,
			    (htab->elf.iplt->output_section->vma
			     + htab->elf.iplt->output_offset
			     + h->plt.offset),
			    sgot->contents + h->got.offset);
		return true;
	      }
	  }
	else if (SYMBOL_REFERENCES_LOCAL (info, h))
	  {
	    if (UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	      return true;

	    if (!(h->def_regular || ELF_COMMON_DEF_P (h)))
	      return false;

	    BFD_ASSERT ((h->got.offset & 1) != 0);
	    rela.r_info = ELF32_R_INFO (0, R_390_RELATIVE);
	    rela.r_addend = (h->root.u.def.value
			     + h->root.u.def.section->output_section->vma
			     + h->root.u.def.section->output_offset);
	  }
	else
	  {
	    BFD_ASSERT ((h->got.offset & 1) == 0);
	  do_glob_dat:
	    bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + h->got.offset);
	    rela.r_info = ELF32_R_INFO (h->dynindx, R_390_GLOB_DAT);
	    rela.r_addend = 0;
	  }

	loc = srelgot->contents + srelgot->reloc_count++ * sizeof (Elf32_External_Rela);
	bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
      }
  }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      if (h->dynindx == -1
	  || (h->root.type != bfd_link_hash_defined
	      && h->root.type != bfd_link_hash_defweak)
	  || htab->elf.srelbss == NULL
	  || htab->elf.sreldynrelro == NULL)
	abort ();

      rela.r_offset = (h->root.u.def.value
		       + h->root.u.def.section->output_section->vma
		       + h->root.u.def.section->output_offset);
      rela.r_info = ELF32_R_INFO (h->dynindx, R_390_COPY);
      rela.r_addend = 0;
      s = (h->root.u.def.section == htab->elf.sdynrelro) ? htab->elf.sreldynrelro : htab->elf.srelbss;
      {
	bfd_byte *loc = s->contents + s->reloc_count++ * sizeof (Elf32_External_Rela);
	bfd_elf32_swap_reloca_out (output_bfd, &rela, loc);
      }
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
  if (info == NULL || rela == NULL)
    abort ();

  bfd *abfd = info->output_bfd;
  if (abfd == NULL)
    abort ();

  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  if (bed == NULL || bed->s == NULL)
    abort ();

  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  if (htab == NULL || htab->elf.dynsym == NULL || htab->elf.dynsym->contents == NULL)
    abort ();

  unsigned long r_symndx = ELF32_R_SYM (rela->r_info);

  if (htab->elf.dynsym->size / bed->s->sizeof_sym <= r_symndx)
    abort ();

  Elf_Internal_Sym sym;
  if (!bed->s->swap_symbol_in (abfd,
                               htab->elf.dynsym->contents + r_symndx * bed->s->sizeof_sym,
                               0, &sym))
    abort ();

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
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table (info);
  bfd *dynobj;
  asection *sdyn = NULL;
  bfd *ibfd;
  unsigned int i;

  if (htab == NULL)
    return false;

  dynobj = htab->elf.dynobj;
  if (dynobj != NULL)
    sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (htab->elf.dynamic_sections_created)
    {
      Elf32_External_Dyn *dyncon, *dynconend;

      if (sdyn == NULL || htab->elf.sgot == NULL)
	return false;

      dyncon = (Elf32_External_Dyn *) sdyn->contents;
      dynconend = (Elf32_External_Dyn *) (sdyn->contents + sdyn->size);
      for (; dyncon < dynconend; dyncon++)
	{
	  Elf_Internal_Dyn dyn;

	  bfd_elf32_swap_dyn_in (dynobj, dyncon, &dyn);

	  switch (dyn.d_tag)
	    {
	    default:
	      continue;

	    case DT_PLTGOT:
	      {
		asection *s = htab->elf.sgotplt;
		if (s == NULL || s->output_section == NULL)
		  return false;
		dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	      }
	      break;

	    case DT_JMPREL:
	      {
		asection *s = htab->elf.srelplt;
		if (s == NULL || s->output_section == NULL)
		  return false;
		dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	      }
	      break;

	    case DT_PLTRELSZ:
	      {
		bfd_size_type sz = 0;
		if (htab->elf.srelplt)
		  sz += htab->elf.srelplt->size;
		if (htab->elf.irelplt)
		  sz += htab->elf.irelplt->size;
		dyn.d_un.d_val = sz;
	      }
	      break;
	    }

	  bfd_elf32_swap_dyn_out (output_bfd, &dyn, dyncon);
	}

      if (htab->elf.splt && htab->elf.splt->size > 0)
	{
	  asection *splt = htab->elf.splt;
	  if (splt->contents == NULL)
	    return false;

	  memset (splt->contents, 0, PLT_FIRST_ENTRY_SIZE);
	  if (bfd_link_pic (info))
	    {
	      memcpy (splt->contents, elf_s390_plt_pic_first_entry,
		      PLT_FIRST_ENTRY_SIZE);
	    }
	  else
	    {
	      if (htab->elf.sgotplt == NULL
		  || htab->elf.sgotplt->output_section == NULL)
		return false;

	      memcpy (splt->contents, elf_s390_plt_first_entry,
		      PLT_FIRST_ENTRY_SIZE);
	      bfd_put_32 (output_bfd,
			  htab->elf.sgotplt->output_section->vma
			  + htab->elf.sgotplt->output_offset,
			  splt->contents + 24);
	    }

	  if (splt->output_section == NULL)
	    return false;
	  elf_section_data (splt->output_section)->this_hdr.sh_entsize = 4;
	}
    }

  if (htab->elf.sgotplt)
    {
      asection *sgotplt = htab->elf.sgotplt;

      if (sgotplt->size > 0)
	{
	  bfd_vma dynptr = 0;

	  if (sgotplt->contents == NULL)
	    return false;

	  if (sdyn != NULL)
	    {
	      if (sdyn->output_section == NULL)
		return false;
	      dynptr = sdyn->output_section->vma + sdyn->output_offset;
	    }

	  bfd_put_32 (output_bfd, dynptr, sgotplt->contents);
	  bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents + 4);
	  bfd_put_32 (output_bfd, (bfd_vma) 0, sgotplt->contents + 8);
	}

      if (sgotplt->output_section == NULL)
	return false;
      elf_section_data (sgotplt->output_section)->this_hdr.sh_entsize = 4;
    }

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      struct plt_entry *local_plt;
      Elf_Internal_Shdr *symtab_hdr;

      if (!is_s390_elf (ibfd))
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      local_plt = elf_s390_local_plt (ibfd);
      if (local_plt == NULL)
	continue;

      for (i = 0; i < symtab_hdr->sh_info; i++)
	{
	  if (local_plt[i].plt.offset != (bfd_vma) -1)
	    {
	      asection *sec = local_plt[i].sec;
	      Elf_Internal_Sym *isym;

	      if (sec == NULL || sec->output_section == NULL)
		return false;

	      isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache, ibfd, i);
	      if (isym == NULL)
		return false;

	      if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
		elf_s390_finish_ifunc_symbol (output_bfd, info, NULL, htab,
					      local_plt[i].plt.offset,
					      isym->st_value
					      + sec->output_section->vma
					      + sec->output_offset);
	    }
	}
    }
  return true;
}

/* Support for core dump NOTE sections.  */

static bool
elf_s390_grok_prstatus(bfd *abfd, Elf_Internal_Note *note)
{
  const unsigned int expected_descsz = 224U;
  const unsigned int pr_cursig_off = 12U;
  const unsigned int pr_pid_off = 24U;
  const int pr_reg_off = 72;
  const unsigned int pr_reg_size = 144U;

  if (abfd == NULL || note == NULL || note->descdata == NULL)
    return false;

  if (note->descsz != expected_descsz)
    return false;

  if (elf_tdata(abfd) == NULL || elf_tdata(abfd)->core == NULL)
    return false;

  if (note->descsz < pr_pid_off + 4U)
    return false;

  elf_tdata(abfd)->core->signal = bfd_get_16(abfd, note->descdata + pr_cursig_off);
  elf_tdata(abfd)->core->lwpid = bfd_get_32(abfd, note->descdata + pr_pid_off);

  if (note->descsz < (unsigned int)(pr_reg_off) + pr_reg_size)
    return false;

  return _bfd_elfcore_make_pseudosection(abfd, ".reg",
                                         pr_reg_size, note->descpos + pr_reg_off);
}

static bool
elf_s390_grok_psinfo(bfd *abfd, Elf_Internal_Note *note)
{
  char *program = NULL;
  char *command = NULL;

  if (abfd == NULL || note == NULL || note->descdata == NULL)
    return false;
  if (elf_tdata(abfd) == NULL || elf_tdata(abfd)->core == NULL)
    return false;
  if (note->descsz != 124)
    return false;

  elf_tdata(abfd)->core->pid = bfd_get_32(abfd, note->descdata + 12);
  program = _bfd_elfcore_strndup(abfd, note->descdata + 28, 16);
  command = _bfd_elfcore_strndup(abfd, note->descdata + 44, 80);

  if (command != NULL)
    {
      size_t n = strlen(command);
      if (n > 0 && command[n - 1] == ' ')
        command[n - 1] = '\0';
    }

  elf_tdata(abfd)->core->program = program;
  elf_tdata(abfd)->core->command = command;

  return true;
}

static size_t bounded_strnlen_local(const char *s, size_t maxlen)
{
  size_t n = 0;
  if (s == NULL)
    return 0;
  while (n < maxlen && s[n] != '\0')
    n++;
  return n;
}

static void copy_fixed_field(char *dst, size_t dst_size, const char *src)
{
  if (dst == NULL || dst_size == 0 || src == NULL)
    return;
  size_t n = bounded_strnlen_local(src, dst_size);
  if (n > 0)
    memcpy(dst, src, n);
}

static char *
elf_s390_write_core_note (bfd *abfd, char *buf, int *bufsiz,
			  int note_type, ...)
{
  if (buf == NULL || bufsiz == NULL)
    return NULL;

  va_list ap;

  switch (note_type)
    {
    default:
      return NULL;

    case NT_PRPSINFO:
      {
        enum { DATA_SIZE = 124, FNAME_OFF = 28, FNAME_LEN = 16, PSARGS_OFF = 44, PSARGS_LEN = 80 };
	char data[DATA_SIZE] ATTRIBUTE_NONSTRING = { 0 };
	const char *fname, *psargs;

	va_start (ap, note_type);
	fname = va_arg (ap, const char *);
	psargs = va_arg (ap, const char *);
	va_end (ap);

        copy_fixed_field (data + FNAME_OFF, FNAME_LEN, fname);
        copy_fixed_field (data + PSARGS_OFF, PSARGS_LEN, psargs);

	return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				   data, sizeof (data));
      }

    case NT_PRSTATUS:
      {
        enum { DATA_SIZE = 224, CURSIG_OFF = 12, PID_OFF = 24, GREGS_OFF = 72, GREGS_SIZE = 144 };
	char data[DATA_SIZE] = { 0 };
	long pid;
	int cursig;
	const void *gregs;

	va_start (ap, note_type);
	pid = va_arg (ap, long);
	cursig = va_arg (ap, int);
	gregs = va_arg (ap, const void *);
	va_end (ap);

	bfd_put_16 (abfd, cursig, (void *) (data + CURSIG_OFF));
	bfd_put_32 (abfd, pid, (void *) (data + PID_OFF));
	if (gregs != NULL)
	  memcpy (data + GREGS_OFF, gregs, GREGS_SIZE);

	return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				   data, sizeof (data));
      }
    }
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
elf_s390_plt_sym_val(bfd_vma index, const asection *plt,
                     const arelent *rel ATTRIBUTE_UNUSED)
{
  const bfd_vma base = plt->vma;
  const bfd_vma first_entry_size = PLT_FIRST_ENTRY_SIZE;
  const bfd_vma entry_size = PLT_ENTRY_SIZE;

  return base + first_entry_size + index * entry_size;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bool
elf32_s390_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  if (ibfd == NULL || info == NULL || info->output_bfd == NULL)
    return false;

  bfd *obfd = info->output_bfd;

  if (!is_s390_elf (ibfd) || !is_s390_elf (obfd))
    return true;

  if (!elf_s390_merge_obj_attributes (ibfd, info))
    return false;

  Elf_Internal_Ehdr *in_hdr = elf_elfheader (ibfd);
  Elf_Internal_Ehdr *out_hdr = elf_elfheader (obfd);
  if (in_hdr == NULL || out_hdr == NULL)
    return false;

  out_hdr->e_flags |= in_hdr->e_flags;
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
