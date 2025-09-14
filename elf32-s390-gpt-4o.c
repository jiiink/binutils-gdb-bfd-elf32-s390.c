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
elf_s390_reloc_type_lookup(bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code) {
    static const reloc_howto_type *reloc_table[] = {
        [BFD_RELOC_NONE] = &elf_howto_table[(int) R_390_NONE],
        [BFD_RELOC_8] = &elf_howto_table[(int) R_390_8],
        [BFD_RELOC_390_12] = &elf_howto_table[(int) R_390_12],
        [BFD_RELOC_16] = &elf_howto_table[(int) R_390_16],
        [BFD_RELOC_32] = &elf_howto_table[(int) R_390_32],
        [BFD_RELOC_CTOR] = &elf_howto_table[(int) R_390_32],
        [BFD_RELOC_32_PCREL] = &elf_howto_table[(int) R_390_PC32],
        [BFD_RELOC_390_GOT12] = &elf_howto_table[(int) R_390_GOT12],
        [BFD_RELOC_32_GOT_PCREL] = &elf_howto_table[(int) R_390_GOT32],
        [BFD_RELOC_390_PLT32] = &elf_howto_table[(int) R_390_PLT32],
        [BFD_RELOC_390_COPY] = &elf_howto_table[(int) R_390_COPY],
        [BFD_RELOC_390_GLOB_DAT] = &elf_howto_table[(int) R_390_GLOB_DAT],
        [BFD_RELOC_390_JMP_SLOT] = &elf_howto_table[(int) R_390_JMP_SLOT],
        [BFD_RELOC_390_RELATIVE] = &elf_howto_table[(int) R_390_RELATIVE],
        [BFD_RELOC_32_GOTOFF] = &elf_howto_table[(int) R_390_GOTOFF32],
        [BFD_RELOC_390_GOTPC] = &elf_howto_table[(int) R_390_GOTPC],
        [BFD_RELOC_390_GOT16] = &elf_howto_table[(int) R_390_GOT16],
        [BFD_RELOC_16_PCREL] = &elf_howto_table[(int) R_390_PC16],
        [BFD_RELOC_390_PC12DBL] = &elf_howto_table[(int) R_390_PC12DBL],
        [BFD_RELOC_390_PLT12DBL] = &elf_howto_table[(int) R_390_PLT12DBL],
        [BFD_RELOC_390_PC16DBL] = &elf_howto_table[(int) R_390_PC16DBL],
        [BFD_RELOC_390_PLT16DBL] = &elf_howto_table[(int) R_390_PLT16DBL],
        [BFD_RELOC_390_PC24DBL] = &elf_howto_table[(int) R_390_PC24DBL],
        [BFD_RELOC_390_PLT24DBL] = &elf_howto_table[(int) R_390_PLT24DBL],
        [BFD_RELOC_390_PC32DBL] = &elf_howto_table[(int) R_390_PC32DBL],
        [BFD_RELOC_390_PLT32DBL] = &elf_howto_table[(int) R_390_PLT32DBL],
        [BFD_RELOC_390_GOTPCDBL] = &elf_howto_table[(int) R_390_GOTPCDBL],
        [BFD_RELOC_390_GOTENT] = &elf_howto_table[(int) R_390_GOTENT],
        [BFD_RELOC_16_GOTOFF] = &elf_howto_table[(int) R_390_GOTOFF16],
        [BFD_RELOC_390_GOTPLT12] = &elf_howto_table[(int) R_390_GOTPLT12],
        [BFD_RELOC_390_GOTPLT16] = &elf_howto_table[(int) R_390_GOTPLT16],
        [BFD_RELOC_390_GOTPLT32] = &elf_howto_table[(int) R_390_GOTPLT32],
        [BFD_RELOC_390_GOTPLTENT] = &elf_howto_table[(int) R_390_GOTPLTENT],
        [BFD_RELOC_390_PLTOFF16] = &elf_howto_table[(int) R_390_PLTOFF16],
        [BFD_RELOC_390_PLTOFF32] = &elf_howto_table[(int) R_390_PLTOFF32],
        [BFD_RELOC_390_TLS_LOAD] = &elf_howto_table[(int) R_390_TLS_LOAD],
        [BFD_RELOC_390_TLS_GDCALL] = &elf_howto_table[(int) R_390_TLS_GDCALL],
        [BFD_RELOC_390_TLS_LDCALL] = &elf_howto_table[(int) R_390_TLS_LDCALL],
        [BFD_RELOC_390_TLS_GD32] = &elf_howto_table[(int) R_390_TLS_GD32],
        [BFD_RELOC_390_TLS_GOTIE12] = &elf_howto_table[(int) R_390_TLS_GOTIE12],
        [BFD_RELOC_390_TLS_GOTIE32] = &elf_howto_table[(int) R_390_TLS_GOTIE32],
        [BFD_RELOC_390_TLS_LDM32] = &elf_howto_table[(int) R_390_TLS_LDM32],
        [BFD_RELOC_390_TLS_IE32] = &elf_howto_table[(int) R_390_TLS_IE32],
        [BFD_RELOC_390_TLS_IEENT] = &elf_howto_table[(int) R_390_TLS_IEENT],
        [BFD_RELOC_390_TLS_LE32] = &elf_howto_table[(int) R_390_TLS_LE32],
        [BFD_RELOC_390_TLS_LDO32] = &elf_howto_table[(int) R_390_TLS_LDO32],
        [BFD_RELOC_390_TLS_DTPMOD] = &elf_howto_table[(int) R_390_TLS_DTPMOD],
        [BFD_RELOC_390_TLS_DTPOFF] = &elf_howto_table[(int) R_390_TLS_DTPOFF],
        [BFD_RELOC_390_TLS_TPOFF] = &elf_howto_table[(int) R_390_TLS_TPOFF],
        [BFD_RELOC_390_20] = &elf_howto_table[(int) R_390_20],
        [BFD_RELOC_390_GOT20] = &elf_howto_table[(int) R_390_GOT20],
        [BFD_RELOC_390_GOTPLT20] = &elf_howto_table[(int) R_390_GOTPLT20],
        [BFD_RELOC_390_TLS_GOTIE20] = &elf_howto_table[(int) R_390_TLS_GOTIE20],
        [BFD_RELOC_390_IRELATIVE] = &elf_howto_table[(int) R_390_IRELATIVE],
        [BFD_RELOC_VTABLE_INHERIT] = &elf32_s390_vtinherit_howto,
        [BFD_RELOC_VTABLE_ENTRY] = &elf32_s390_vtentry_howto
    };

    if (code >= 0 && code < sizeof(reloc_table) / sizeof(reloc_table[0]) && reloc_table[code] != NULL) {
        return (reloc_howto_type *) reloc_table[code];
    }
    return NULL;
}

static reloc_howto_type *elf_s390_reloc_name_lookup(bfd *abfd ATTRIBUTE_UNUSED, const char *r_name) {
    size_t i, howto_table_size = sizeof(elf_howto_table) / sizeof(elf_howto_table[0]);
    const reloc_howto_type *special_cases[] = {&elf32_s390_vtinherit_howto, &elf32_s390_vtentry_howto};

    for (i = 0; i < howto_table_size; i++) {
        if (elf_howto_table[i].name && strcasecmp(elf_howto_table[i].name, r_name) == 0) {
            return &elf_howto_table[i];
        }
    }

    for (i = 0; i < sizeof(special_cases) / sizeof(special_cases[0]); i++) {
        if (strcasecmp(special_cases[i]->name, r_name) == 0) {
            return (reloc_howto_type *)special_cases[i];
        }
    }

    return NULL;
}

/* We need to use ELF32_R_TYPE so we have our own copy of this function,
   and elf32-s390.c has its own copy.  */

bool elf_s390_info_to_howto(bfd *abfd, arelent *cache_ptr, Elf_Internal_Rela *dst) {
    unsigned int r_type = ELF32_R_TYPE(dst->r_info);

    if (r_type == R_390_GNU_VTINHERIT) {
        cache_ptr->howto = &elf32_s390_vtinherit_howto;
    } else if (r_type == R_390_GNU_VTENTRY) {
        cache_ptr->howto = &elf32_s390_vtentry_howto;
    } else if (r_type < sizeof(elf_howto_table) / sizeof(elf_howto_table[0])) {
        cache_ptr->howto = &elf_howto_table[r_type];
    } else {
        _bfd_error_handler(_("%pB: unsupported relocation type %#x"), abfd, r_type);
        bfd_set_error(bfd_error_bad_value);
        return false;
    }

    return true;
}

/* A relocation function which doesn't do anything.  */
static bfd_reloc_status_type s390_tls_reloc(bfd *output_bfd, arelent *reloc_entry, asection *input_section) {
  if (output_bfd != NULL) {
    reloc_entry->address += input_section->output_offset;
  }
  return bfd_reloc_ok;
}

/* Handle the large displacement relocs.  */
static bfd_reloc_status_type
s390_elf_ldisp_reloc(bfd *abfd,
                     arelent *reloc_entry,
                     asymbol *symbol,
                     void *data,
                     asection *input_section,
                     bfd *output_bfd,
                     char **error_message)
{
    if (output_bfd != NULL && (symbol->flags & BSF_SECTION_SYM) == 0 && 
        (!reloc_entry->howto->partial_inplace || reloc_entry->addend == 0))
    {
        reloc_entry->address += input_section->output_offset;
        return bfd_reloc_ok;
    }

    if (output_bfd != NULL)
    {
        return bfd_reloc_continue;
    }

    if (reloc_entry->address > bfd_get_section_limit(abfd, input_section))
    {
        return bfd_reloc_outofrange;
    }

    bfd_vma relocation = symbol->value + symbol->section->output_section->vma + 
                         symbol->section->output_offset + reloc_entry->addend;

    if (reloc_entry->howto->pc_relative)
    {
        relocation -= input_section->output_section->vma;
        relocation -= input_section->output_offset;
        relocation -= reloc_entry->address;
    }

    bfd_vma insn = bfd_get_32(abfd, (bfd_byte *)data + reloc_entry->address);
    insn |= (relocation & 0xfff) << 16 | (relocation & 0xff000) >> 4;
    bfd_put_32(abfd, insn, (bfd_byte *)data + reloc_entry->address);

    if ((bfd_signed_vma)relocation < -0x80000 || (bfd_signed_vma)relocation > 0x7ffff)
    {
        return bfd_reloc_overflow;
    }
    return bfd_reloc_ok;
}

static bool elf_s390_is_local_label_name(bfd *abfd, const char *name) {
    return (name[0] == '.' && (name[1] == 'X' || name[1] == 'L')) || 
           _bfd_elf_is_local_label_name(abfd, name);
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

static bool elf_s390_mkobject(bfd *abfd) {
    if (!abfd) {
        return false;
    }
    size_t tdata_size = sizeof(struct elf_s390_obj_tdata);
    return bfd_elf_allocate_object(abfd, tdata_size);
}

#include <stdbool.h>
#include "bfd.h"

static bool elf_s390_object_p(bfd *abfd) {
    if (abfd == NULL) {
        return false;
    }
    return bfd_default_set_arch_mach(abfd, bfd_arch_s390, bfd_mach_s390_31);
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

static struct bfd_hash_entry *link_hash_newfunc(struct bfd_hash_entry *entry, struct bfd_hash_table *table, const char *string) {
    if (entry == NULL) {
        entry = bfd_hash_allocate(table, sizeof(struct elf_s390_link_hash_entry));
        if (entry == NULL) return NULL;
    }

    entry = _bfd_elf_link_hash_newfunc(entry, table, string);
    if (entry == NULL) return NULL;

    struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry *)entry;
    eh->gotplt_refcount = 0;
    eh->tls_type = GOT_UNKNOWN;
    eh->ifunc_resolver_address = 0;
    eh->ifunc_resolver_section = NULL;
    
    return entry;
}

/* Create an s390 ELF linker hash table.  */

static struct bfd_link_hash_table *elf_s390_link_hash_table_create(bfd *abfd) {
    struct elf_s390_link_hash_table *ret = (struct elf_s390_link_hash_table *)bfd_zmalloc(sizeof(struct elf_s390_link_hash_table));
    if (ret == NULL || !_bfd_elf_link_hash_table_init(&ret->elf, abfd, link_hash_newfunc, sizeof(struct elf_s390_link_hash_entry))) {
        free(ret);
        return NULL;
    }
    return &ret->elf.root;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void elf_s390_copy_indirect_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *dir, struct elf_link_hash_entry *ind) {
    struct elf_s390_link_hash_entry *edir = (struct elf_s390_link_hash_entry *)dir;
    struct elf_s390_link_hash_entry *eind = (struct elf_s390_link_hash_entry *)ind;

    if (ind->root.type == bfd_link_hash_indirect && dir->got.refcount <= 0) {
        edir->tls_type = eind->tls_type;
        eind->tls_type = GOT_UNKNOWN;
    }

    if (ELIMINATE_COPY_RELOCS && ind->root.type != bfd_link_hash_indirect && dir->dynamic_adjusted) {
        if (dir->versioned != versioned_hidden) {
            dir->ref_dynamic |= ind->ref_dynamic;
        }
        dir->ref_regular |= ind->ref_regular;
        dir->ref_regular_nonweak |= ind->ref_regular_nonweak;
        dir->needs_plt |= ind->needs_plt;
    } else {
        _bfd_elf_link_hash_copy_indirect(info, dir, ind);
    }
}

static int elf_s390_tls_transition(struct bfd_link_info *info, int r_type, int is_local) {
    if (bfd_link_pic(info)) {
        return r_type;
    }

    switch (r_type) {
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

static bool elf_s390_check_relocs(bfd *abfd, struct bfd_link_info *info, asection *sec, const Elf_Internal_Rela *relocs) {
    if (bfd_link_relocatable(info)) return true;

    BFD_ASSERT(is_s390_elf(abfd));

    struct elf_s390_link_hash_table *htab = elf_s390_hash_table(info);
    Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr(abfd);
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(abfd);
    bfd_signed_vma *local_got_refcounts = elf_local_got_refcounts(abfd);

    const Elf_Internal_Rela *rel_end = relocs + sec->reloc_count;
    asection *sreloc = NULL;

    for (const Elf_Internal_Rela *rel = relocs; rel < rel_end; rel++) {
        unsigned int r_symndx = ELF32_R_SYM(rel->r_info);
        if (r_symndx >= NUM_SHDR_ENTRIES(symtab_hdr)) {
            _bfd_error_handler(_("%pB: bad symbol index: %d"), abfd, r_symndx);
            return false;
        }

        struct elf_link_hash_entry *h = NULL;
        Elf_Internal_Sym *isym = NULL;

        if (r_symndx < symtab_hdr->sh_info) {
            isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, abfd, r_symndx);
            if (!isym) return false;

            if (ELF_ST_TYPE(isym->st_info) == STT_GNU_IFUNC) {
                if (!htab->elf.dynobj) htab->elf.dynobj = abfd;
                if (!s390_elf_create_ifunc_sections(htab->elf.dynobj, info)) return false;

                if (!local_got_refcounts) {
                    if (!elf_s390_allocate_local_syminfo(abfd, symtab_hdr)) return false;
                    local_got_refcounts = elf_local_got_refcounts(abfd);
                }
                struct plt_entry *plt = elf_s390_local_plt(abfd);
                plt[r_symndx].plt.refcount++;
            }
        } else {
            h = sym_hashes[r_symndx - symtab_hdr->sh_info];
            while (h->root.type == bfd_link_hash_indirect || h->root.type == bfd_link_hash_warning) {
                h = (struct elf_link_hash_entry *)h->root.u.i.link;
            }
        }

        unsigned int r_type = elf_s390_tls_transition(info, ELF32_R_TYPE(rel->r_info), h == NULL);
        if (r_type >= R_390_GOT12 && r_type <= R_390_TLS_IEENT && !local_got_refcounts) {
            if (!elf_s390_allocate_local_syminfo(abfd, symtab_hdr)) return false;
            local_got_refcounts = elf_local_got_refcounts(abfd);
        }

        if (r_type >= R_390_GOT12 && r_type <= R_390_GOTPLTENT) {
            if (!htab->elf.sgot && !create_got_and_plt_sections(abfd, info, htab)) return false;
        }

        if (h) {
            manage_plt_and_got_entries(info, abfd, h, r_type, r_symndx, local_got_refcounts);
        } else {
            local_got_refcounts[r_symndx]++;
        }

        if (!process_relocation_cases(info, abfd, sec, rel, r_type, h, local_got_refcounts, &sreloc)) return false;
    }

    return true;
}

bool create_got_and_plt_sections(bfd *abfd, struct bfd_link_info *info, struct elf_s390_link_hash_table *htab) {
    if (!htab->elf.dynobj) htab->elf.dynobj = abfd;
    if (!_bfd_elf_create_got_section(htab->elf.dynobj, info)) return false;
    return true;
}

void manage_plt_and_got_entries(struct bfd_link_info *info, bfd *abfd, struct elf_link_hash_entry *h, unsigned int r_type, unsigned int r_symndx, bfd_signed_vma *local_got_refcounts) {
    if (!elf_s390_hash_entry(h)->plt.refcount && h->def_regular) {
        h->needs_plt = (r_type >= R_390_GOT12 && r_type <= R_390_TLS_IEENT);
        if (!(r_type >= R_390_GOT12 && r_type < R_390_PLT32)) {
            if (ELIMINATE_COPY_RELOCS && !bfd_link_pic(info) && local_got_refcounts[r_symndx]) {
                h->non_got_ref = 1;
            }
        }
    }

    if (r_type >= R_390_GOTPLT12 && r_type <= R_390_TLS_IEENT) {
        manage_tls_entries(info, h, r_type);
    }
}

void manage_tls_entries(struct bfd_link_info *info, struct elf_link_hash_entry *h, unsigned int r_type) {
    switch (r_type) {
        case R_390_TLS_IE32:
            info->flags |= DF_STATIC_TLS;
            break;
        default:
            break;
    }
    h->got.refcount++;
}

bool process_relocation_cases(struct bfd_link_info *info, bfd *abfd, asection *sec, const Elf_Internal_Rela *rel, unsigned int r_type, struct elf_link_hash_entry *h, bfd_signed_vma *local_got_refcounts, asection **sreloc) {
    switch (r_type) {
        case R_390_8:
        case R_390_16:
        case R_390_32:
        case R_390_PC16:
        case R_390_PC12DBL:
        case R_390_PC16DBL:
        case R_390_PC24DBL:
        case R_390_PC32DBL:
        case R_390_PC32:
            return process_common_relocation_cases(info, abfd, sec, rel, h, sreloc);

        case R_390_TLS_IE32:
            if (process_tls_case_ie32(info, sec, h, local_got_refcounts)) return true;
        
        case R_390_TLS_LE32:
            if (process_tls_case_le32(info)) return true;

        default:
            return true;
    }
}

bool process_common_relocation_cases(struct bfd_link_info *info, bfd *abfd, asection *sec, const Elf_Internal_Rela *rel, struct elf_link_hash_entry *h, asection **sreloc) {
    if ((bfd_link_pic(info) && (sec->flags & SEC_ALLOC) && (r_type_among_pc_rel_cases(rel))) || elim_copy_and_sec_alloc(info, sec, h)) {
        if (!process_relocation_section(info, abfd, sec, h, sreloc)) return false;
    }

    return true;
}

bool process_tls_case_ie32(struct bfd_link_info *info, asection *sec, struct elf_link_hash_entry *h, bfd_signed_vma *local_got_refcounts) {
    if (bfd_link_pic(info) && (sec->flags & SEC_ALLOC)) {
        process_relocation_case_tls(h, local_got_refcounts);
        return true;
    }
    return false;
}

bool process_tls_case_le32(struct bfd_link_info *info) {
    if (bfd_link_pie(info)) return false;
    if (bfd_link_pic(info)) return false;
    return true;
}

bool process_relocation_section(struct bfd_link_info *info, bfd *abfd, asection *sec, struct elf_link_hash_entry *h, asection **sreloc) {
    if (!*sreloc) {
        if (!_bfd_elf_make_dynamic_reloc_section(sec, abfd, 2, abfd, true)) return false;
    }

    struct elf_dyn_relocs **head = (h) ? &h->dyn_relocs : NULL;
    struct elf_dyn_relocs *p = *head;
    if (!p || p->sec != sec) {
        p = allocate_rel_dyn_memory(htab, head);
        if (!p) return false;
    }

    p->count++;
    return true;
}

bool r_type_among_pc_rel_cases(const Elf_Internal_Rela *rel) {
    return (&ELF32_R_TYPE(rel->r_info) != R_390_PC16DBL && 
            &ELF32_R_TYPE(rel->r_info) != R_390_PC24DBL && 
            &ELF32_R_TYPE(rel->r_info) != R_390_PC32DBL && 
            &ELF32_R_TYPE(rel->r_info) != R_390_PC32);
}

bool elim_copy_and_sec_alloc(struct bfd_link_info *info, asection *sec, struct elf_link_hash_entry *h) {
    return (ELIMINATE_COPY_RELOCS && !bfd_link_pic(info) && (sec->flags & SEC_ALLOC) && h &&
            (h->root.type == bfd_link_hash_defweak || !h->def_regular));
}

struct elf_dyn_relocs *allocate_rel_dyn_memory(struct elf_s390_link_hash_table *htab, struct elf_dyn_relocs **head) {
    struct elf_dyn_relocs *p = (struct elf_dyn_relocs *)bfd_alloc(htab->elf.dynobj, sizeof *p);
    if (p) {
        p->next = *head;
        *head = p;
        p->sec = sec;
        p->count = 0;
        p->pc_count = 0;
    }
    return p;
}

/* Return the section that should be marked against GC for a given
   relocation.  */

static asection *elf_s390_gc_mark_hook(asection *sec, struct bfd_link_info *info, Elf_Internal_Rela *rel, struct elf_link_hash_entry *h, Elf_Internal_Sym *sym) {
    if (h != NULL && (ELF32_R_TYPE(rel->r_info) == R_390_GNU_VTINHERIT || ELF32_R_TYPE(rel->r_info) == R_390_GNU_VTENTRY)) {
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

static void elf_s390_adjust_gotplt(struct elf_s390_link_hash_entry *h) {
    if (h->elf.root.type == bfd_link_hash_warning) {
        h = (struct elf_s390_link_hash_entry *)h->elf.root.u.i.link;
    }

    if (h->gotplt_refcount > 0) {
        h->elf.got.refcount += h->gotplt_refcount;
        h->gotplt_refcount = -1;
    }
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bool elf_s390_adjust_dynamic_symbol(struct bfd_link_info *info, struct elf_link_hash_entry *h) {
    struct elf_s390_link_hash_table *htab;
    asection *s, *srel;

    if (s390_is_ifunc_symbol_p(h)) {
        if (h->ref_regular && SYMBOL_CALLS_LOCAL(info, h)) {
            bfd_size_type pc_count = 0, count = 0;
            struct elf_dyn_relocs **pp = &h->dyn_relocs;
            struct elf_dyn_relocs *p = *pp;

            while (p) {
                pc_count += p->pc_count;
                p->count -= p->pc_count;
                p->pc_count = 0;
                count += p->count;
                if (p->count == 0) {
                    *pp = p->next;
                } else {
                    pp = &p->next;
                }
                p = *pp;
            }

            if (pc_count || count) {
                h->needs_plt = 1;
                h->non_got_ref = 1;
                h->plt.refcount = h->plt.refcount <= 0 ? 1 : h->plt.refcount + 1;
            }
        }

        if (h->plt.refcount <= 0) {
            h->plt.offset = (bfd_vma) -1;
            h->needs_plt = 0;
        }
        return true;
    }

    if (h->type == STT_FUNC || h->needs_plt) {
        if (h->plt.refcount <= 0 || SYMBOL_CALLS_LOCAL(info, h) || UNDEFWEAK_NO_DYNAMIC_RELOC(info, h)) {
            h->plt.offset = (bfd_vma) -1;
            h->needs_plt = 0;
            elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *)h);
        }
        return true;
    } else {
        h->plt.offset = (bfd_vma) -1;
    }

    if (h->is_weakalias) {
        struct elf_link_hash_entry *def = weakdef(h);
        BFD_ASSERT(def->root.type == bfd_link_hash_defined);
        h->root.u.def.section = def->root.u.def.section;
        h->root.u.def.value = def->root.u.def.value;
        if (ELIMINATE_COPY_RELOCS || info->nocopyreloc) {
            h->non_got_ref = def->non_got_ref;
        }
        return true;
    }

    if (bfd_link_pic(info)) {
        return true;
    }

    if (!h->non_got_ref || info->nocopyreloc || (ELIMINATE_COPY_RELOCS && !_bfd_elf_readonly_dynrelocs(h))) {
        h->non_got_ref = 0;
        return true;
    }

    htab = elf_s390_hash_table(info);

    if ((h->root.u.def.section->flags & SEC_READONLY) != 0) {
        s = htab->elf.sdynrelro;
        srel = htab->elf.sreldynrelro;
    } else {
        s = htab->elf.sdynbss;
        srel = htab->elf.srelbss;
    }

    if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0) {
        srel->size += sizeof(Elf32_External_Rela);
        h->needs_copy = 1;
    }

    return _bfd_elf_adjust_dynamic_copy(info, h, s);
}

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bool allocate_dynrelocs(struct elf_link_hash_entry *h, void *inf) {
    if (h->root.type == bfd_link_hash_indirect) {
        return true;
    }

    struct bfd_link_info *info = (struct bfd_link_info *)inf;
    struct elf_s390_link_hash_table *htab = elf_s390_hash_table(info);
    
    if (s390_is_ifunc_symbol_p(h) && h->def_regular) {
        return s390_elf_allocate_ifunc_dyn_relocs(info, h);
    }

    bool dynamic_sections = htab->elf.dynamic_sections_created && h->plt.refcount > 0;
    bool is_got_refcount_positive = h->got.refcount > 0;
    asection *sgotplt = htab->elf.sgotplt;
    asection *srelplt = htab->elf.srelplt;
    asection *sgot = htab->elf.sgot;
    asection *srelgot = htab->elf.srelgot;

    if (dynamic_sections) {
        if (h->dynindx == -1 && !h->forced_local) {
            if (!bfd_elf_link_record_dynamic_symbol(info, h)) {
                return false;
            }
        }
        if (bfd_link_pic(info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL(1, 0, h)) {
            asection *splt = htab->elf.splt;
            if (splt->size == 0) {
                splt->size += PLT_FIRST_ENTRY_SIZE;
            }
            h->plt.offset = splt->size;
            if (!bfd_link_pic(info) && !h->def_regular) {
                h->root.u.def.section = splt;
                h->root.u.def.value = h->plt.offset;
            }
            splt->size += PLT_ENTRY_SIZE;
            sgotplt->size += GOT_ENTRY_SIZE;
            srelplt->size += sizeof(Elf32_External_Rela);
        } else {
            h->plt.offset = (bfd_vma)-1;
            h->needs_plt = 0;
            elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *)h);
        }
    } else {
        h->plt.offset = (bfd_vma)-1;
        h->needs_plt = 0;
        elf_s390_adjust_gotplt((struct elf_s390_link_hash_entry *)h);
    }

    if (is_got_refcount_positive && !bfd_link_pic(info) && h->dynindx == -1 && elf_s390_hash_entry(h)->tls_type >= GOT_TLS_IE) {
        if (elf_s390_hash_entry(h)->tls_type == GOT_TLS_IE_NLT) {
            h->got.offset = sgot->size;
            sgot->size += GOT_ENTRY_SIZE;
        } else {
            h->got.offset = (bfd_vma)-1;
        }
    } else if (is_got_refcount_positive) {
        if (h->dynindx == -1 && !h->forced_local) {
            if (!bfd_elf_link_record_dynamic_symbol(info, h)) return false;
        }
        h->got.offset = sgot->size;
        sgot->size += GOT_ENTRY_SIZE;
        int tls_type = elf_s390_hash_entry(h)->tls_type;
        if (tls_type == GOT_TLS_GD) sgot->size += GOT_ENTRY_SIZE;

        if ((tls_type == GOT_TLS_GD && h->dynindx == -1) || tls_type >= GOT_TLS_IE) {
            srelgot->size += sizeof(Elf32_External_Rela);
        } else if (tls_type == GOT_TLS_GD) {
            srelgot->size += 2 * sizeof(Elf32_External_Rela);
        } else if (!UNDEFWEAK_NO_DYNAMIC_RELOC(info, h) && (bfd_link_pic(info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL(dynamic_sections, 0, h))) {
            srelgot->size += sizeof(Elf32_External_Rela);
        }
    } else {
        h->got.offset = (bfd_vma)-1;
    }

    if (h->dyn_relocs == NULL) return true;

    if (bfd_link_pic(info)) {
        if (SYMBOL_CALLS_LOCAL(info, h)) {
            struct elf_dyn_relocs *prev = NULL;
            for (struct elf_dyn_relocs *p = h->dyn_relocs; p != NULL; ) {
                p->count -= p->pc_count;
                p->pc_count = 0;
                struct elf_dyn_relocs *next = p->next;
                if (p->count == 0) {
                    if (prev) {
                        prev->next = next;
                    } else {
                        h->dyn_relocs = next;
                    }
                } else {
                    prev = p;
                }
                p = next;
            }
        }
        if (h->dyn_relocs != NULL && h->root.type == bfd_link_hash_undefweak) {
            if (ELF_ST_VISIBILITY(h->other) != STV_DEFAULT || UNDEFWEAK_NO_DYNAMIC_RELOC(info, h)) {
                h->dyn_relocs = NULL;
            } else if (h->dynindx == -1 && !h->forced_local) {
                if (!bfd_elf_link_record_dynamic_symbol(info, h)) return false;
            }
        }
    } else if (ELIMINATE_COPY_RELOCS) {
        if (!h->non_got_ref && ((h->def_dynamic && !h->def_regular) || (htab->elf.dynamic_sections_created && (h->root.type == bfd_link_hash_undefweak || h->root.type == bfd_link_hash_undefined)))) {
            if (h->dynindx == -1 && !h->forced_local) {
                if (!bfd_elf_link_record_dynamic_symbol(info, h)) return false;
            }
            if (h->dynindx != -1) goto keep_relocs;
        }
        h->dyn_relocs = NULL;
    keep_relocs:;
    }

    for (struct elf_dyn_relocs *p = h->dyn_relocs; p != NULL; p = p->next) {
        asection *sreloc = elf_section_data(p->sec)->sreloc;
        sreloc->size += p->count * sizeof(Elf32_External_Rela);
    }

    return true;
}

/* Set the sizes of the dynamic sections.  */

#include <stdbool.h>
#include <stddef.h>

static bool elf_s390_late_size_sections(bfd *output_bfd, struct bfd_link_info *info) {
    struct elf_s390_link_hash_table *htab = elf_s390_hash_table(info);
    bfd *dynobj = htab->elf.dynobj;

    if (!dynobj) {
        return true;
    }

    if (htab->elf.dynamic_sections_created) {
        if (bfd_link_executable(info) && !info->nointerp) {
            asection *interp_section = bfd_get_linker_section(dynobj, ".interp");
            if (!interp_section) {
                return false;
            }
            interp_section->size = sizeof(ELF_DYNAMIC_INTERPRETER);
            interp_section->contents = (unsigned char *)ELF_DYNAMIC_INTERPRETER;
            interp_section->alloced = 1;
        }
    }

    for (bfd *ibfd = info->input_bfds; ibfd; ibfd = ibfd->link.next) {
        if (!is_s390_elf(ibfd)) {
            continue;
        }

        for (asection *section = ibfd->sections; section; section = section->next) {
            for (struct elf_dyn_relocs *p = elf_section_data(section)->local_dynrel; p; p = p->next) {
                if (!bfd_is_abs_section(p->sec) && bfd_is_abs_section(p->sec->output_section)) {
                    continue;
                }

                if (p->count > 0) {
                    asection *srela = elf_section_data(p->sec)->sreloc;
                    srela->size += p->count * sizeof(Elf32_External_Rela);
                    if (p->sec->output_section->flags & SEC_READONLY) {
                        info->flags |= DF_TEXTREL;
                    }
                }
            }
        }

        bfd_signed_vma *local_got = elf_local_got_refcounts(ibfd);
        if (!local_got) {
            continue;
        }

        Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr(ibfd);
        bfd_size_type locsymcount = symtab_hdr->sh_info;
        bfd_signed_vma *end_local_got = local_got + locsymcount;
        char *local_tls_type = elf_s390_local_got_tls_type(ibfd);
        asection *got_section = htab->elf.sgot;
        asection *srelgot_section = htab->elf.srelgot;

        for (; local_got < end_local_got; ++local_got, ++local_tls_type) {
            if (*local_got > 0) {
                *local_got = got_section->size;
                got_section->size += GOT_ENTRY_SIZE;
                if (*local_tls_type == GOT_TLS_GD) {
                    got_section->size += GOT_ENTRY_SIZE;
                }
                if (bfd_link_pic(info)) {
                    srelgot_section->size += sizeof(Elf32_External_Rela);
                }
            } else {
                *local_got = (bfd_vma)-1;
            }
        }

        struct plt_entry *local_plt = elf_s390_local_plt(ibfd);
        for (unsigned int i = 0; i < symtab_hdr->sh_info; i++) {
            if (local_plt[i].plt.refcount > 0) {
                local_plt[i].plt.offset = htab->elf.iplt->size;
                htab->elf.iplt->size += PLT_ENTRY_SIZE;
                htab->elf.igotplt->size += GOT_ENTRY_SIZE;
                htab->elf.irelplt->size += RELA_ENTRY_SIZE;
            } else {
                local_plt[i].plt.offset = (bfd_vma)-1;
            }
        }
    }

    if (htab->tls_ldm_got.refcount > 0) {
        htab->tls_ldm_got.offset = htab->elf.sgot->size;
        htab->elf.sgot->size += 2 * GOT_ENTRY_SIZE;
        htab->elf.srelgot->size += sizeof(Elf32_External_Rela);
    } else {
        htab->tls_ldm_got.offset = -1;
    }

    elf_link_hash_traverse(&htab->elf, allocate_dynrelocs, info);

    bool relocs = false;
    for (asection *s = dynobj->sections; s; s = s->next) {
        if (!(s->flags & SEC_LINKER_CREATED)) {
            continue;
        }

        if (s == htab->elf.splt || s == htab->elf.sgot || s == htab->elf.sgotplt ||
            s == htab->elf.sdynbss || s == htab->elf.sdynrelro || 
            s == htab->elf.iplt || s == htab->elf.igotplt || 
            s == htab->irelifunc) {
            /* Strip this section if we don't need it */
        } else if (startswith(bfd_section_name(s), ".rela")) {
            if (s->size != 0) {
                relocs = true;
            }
            s->reloc_count = 0;
        } else {
            continue;
        }

        if (s->size == 0) {
            s->flags |= SEC_EXCLUDE;
            continue;
        }

        if (!(s->flags & SEC_HAS_CONTENTS)) {
            continue;
        }

        s->contents = (bfd_byte *)bfd_zalloc(dynobj, s->size);
        if (!s->contents) {
            return false;
        }
        s->alloced = 1;
    }
    return _bfd_elf_add_dynamic_tags(output_bfd, info, relocs);
}

/* Return the base VMA address which should be subtracted from real addresses
   when resolving @dtpoff relocation.
   This is PT_TLS segment p_vaddr.  */

static bfd_vma dtpoff_base(struct bfd_link_info *info) {
  struct elf_hash_table *hash_table = elf_hash_table(info);
  if (!hash_table || !hash_table->tls_sec) {
    /* Handle the error: return a meaningful error code or take other actions */
    return 0; 
  }
  return hash_table->tls_sec->vma;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma tpoff(struct bfd_link_info *info, bfd_vma address) {
    struct elf_link_hash_table *htab = elf_hash_table(info);

    if (htab->tls_sec == NULL) {
        fprintf(stderr, "Error: tls_sec is NULL\n");
        exit(EXIT_FAILURE);
    }
    return htab->tls_size + htab->tls_sec->vma - address;
}

/* Complain if TLS instruction relocation is against an invalid
   instruction.  */

#include <inttypes.h>
#include <stdio.h>
#include <bfd.h>
#include <libelf.h>

static void invalid_tls_insn(bfd *input_bfd, asection *input_section, Elf_Internal_Rela *rel) {
    if (input_bfd == NULL || input_section == NULL || rel == NULL) {
        bfd_set_error(bfd_error_invalid_operation);
        return;
    }

    reloc_howto_type *howto = elf_howto_table + ELF32_R_TYPE(rel->r_info);

    if (howto == NULL || howto->name == NULL) {
        bfd_set_error(bfd_error_bad_value);
        return;
    }

    _bfd_error_handler("%pB(%pA+%#" PRIx64 "): invalid instruction for TLS relocation %s",
                       input_bfd, input_section, (uint64_t)rel->r_offset, howto->name);
    bfd_set_error(bfd_error_bad_value);
}

/* Relocate a 390 ELF section.  */

static int elf_s390_relocate_section(bfd *output_bfd, struct bfd_link_info *info, bfd *input_bfd, asection *input_section, bfd_byte *contents, Elf_Internal_Rela *relocs, Elf_Internal_Sym *local_syms, asection **local_sections) {
    if (!is_s390_elf(input_bfd)) {
        bfd_set_error(bfd_error_wrong_format);
        return false;
    }

    struct elf_s390_link_hash_table *htab = elf_s390_hash_table(info);
    Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr(input_bfd);
    struct elf_link_hash_entry **sym_hashes = elf_sym_hashes(input_bfd);
    bfd_vma *local_got_offsets = elf_local_got_offsets(input_bfd);

    Elf_Internal_Rela *rel = relocs;
    Elf_Internal_Rela *relend = relocs + input_section->reloc_count;
    for (; rel < relend; rel++) {
        unsigned int r_type = ELF32_R_TYPE(rel->r_info);
        if (r_type >= (int) R_390_max || r_type == (int) R_390_GNU_VTINHERIT || r_type == (int) R_390_GNU_VTENTRY) {
            if (r_type >= (int) R_390_max) {
                bfd_set_error(bfd_error_bad_value);
                return false;
            }
            continue;
        }

        reloc_howto_type *howto = elf_howto_table + r_type;
        unsigned long r_symndx = ELF32_R_SYM(rel->r_info);
        struct elf_link_hash_entry *h = NULL;
        Elf_Internal_Sym *sym = NULL;
        asection *sec = NULL;
        bool unresolved_reloc = false;
        
        bfd_vma relocation = 0;
        if (r_symndx < symtab_hdr->sh_info) {
            sym = local_syms + r_symndx;
            sec = local_sections[r_symndx];
            if (ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
                struct plt_entry *local_plt = elf_s390_local_plt(input_bfd);
                if (local_plt == NULL) return false;

                relocation = htab->elf.iplt->output_section->vma + htab->elf.iplt->output_offset + local_plt[r_symndx].plt.offset;
                switch (r_type) {
                    case R_390_PLTOFF16: case R_390_PLTOFF32:
                        relocation -= htab->elf.sgot->output_section->vma;
                        break;
                    case R_390_GOTPLT12: case R_390_GOTPLT16: case R_390_GOTPLT20: case R_390_GOTPLT32: case R_390_GOTPLTENT:
                    case R_390_GOT12: case R_390_GOT16: case R_390_GOT20: case R_390_GOT32: case R_390_GOTENT:
                        bfd_put_32(output_bfd, relocation, htab->elf.sgot->contents + local_got_offsets[r_symndx]);
                        relocation = local_got_offsets[r_symndx] + htab->elf.sgot->output_offset;
                        if (r_type == R_390_GOTENT || r_type == R_390_GOTPLTENT)
                            relocation += htab->elf.sgot->output_section->vma;
                        break;
                    default:
                        break;
                }
                local_plt[r_symndx].sec = sec;
                continue;
            } else {
                relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);
            }
        } else {
            RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel, r_symndx, symtab_hdr, sym_hashes, h, sec, relocation, unresolved_reloc);
        }

        if (sec && discarded_section(sec)) {
            RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section, rel, 1, relend, R_390_NONE, howto, 0, contents);
        }

        if (bfd_link_relocatable(info)) continue;

        bool resolved_to_zero = (h && UNDEFWEAK_NO_DYNAMIC_RELOC(info, h));
        switch (r_type) {
            case R_390_GOTPLT12: case R_390_GOTPLT16: case R_390_GOTPLT20: case R_390_GOTPLT32: case R_390_GOTPLTENT: 
                handle_PLT_relocation(output_bfd, info, h, input_bfd, input_section, rel, r_type, sym_hashes, base_got);
            case R_390_GOT12: case R_390_GOT16: case R_390_GOT20: case R_390_GOT32: case R_390_GOTENT:
                handle_GOT_relocation(output_bfd, info, h, input_bfd, input_section, rel, r_type, unresolved_reloc, relocation, local_got_offsets, htab);
                break;
            case R_390_GOTOFF16: case R_390_GOTOFF32:
                handle_GOTOFF_relocation(info, h, relocation, htab);
                break;
            case R_390_GOTPC: case R_390_GOTPCDBL:
                relocation = htab->elf.sgot->output_section->vma;
                unresolved_reloc = false;
                break;
            case R_390_PLT12DBL: case R_390_PLT16DBL: case R_390_PLT32DBL: case R_390_PLT32:
                handle_PLT_relocation(output_bfd, info, h, relocation, htab, base_got, sec, unresolved_reloc, relocation, local_got_offsets, htab);
                break;
            default:
                handle_default_case(output_bfd, info, h, input_bfd, input_section, rel_type, r_type, unresolved_reloc, relocation, howto, contents, rel);
                break;
        }

        do_relocation(output_bfd, r_type, relocation, howto, input_bfd, input_section, contents, rel->r_offset, r);
        if (r != bfd_reloc_ok && r != bfd_reloc_overflow) handle_relocation_errors(info, h, input_bfd, input_section, rel, r_type, r);

    }
    return true;
}

/* Generate the PLT slots together with the dynamic relocations needed
   for IFUNC symbols.  */

#include <stdlib.h>
#include <string.h>

static void elf_s390_finish_ifunc_symbol(bfd *output_bfd, struct bfd_link_info *info,
                                         struct elf_link_hash_entry *h, 
                                         struct elf_s390_link_hash_table *htab,
                                         bfd_vma iplt_offset, bfd_vma resolver_address) {
    if (!htab->elf.iplt || !htab->elf.igotplt || !htab->elf.irelplt)
        abort();

    asection *plt = htab->elf.iplt;
    asection *gotplt = htab->elf.igotplt;
    asection *relplt = htab->elf.irelplt;

    bfd_vma iplt_index = iplt_offset / PLT_ENTRY_SIZE;
    bfd_vma igotiplt_offset = iplt_index * GOT_ENTRY_SIZE;
    bfd_vma got_offset = igotiplt_offset + gotplt->output_offset;
    bfd_vma relative_offset = -((plt->output_offset + (PLT_ENTRY_SIZE * iplt_index) + 18) / 2);

    if (relative_offset < -32768)
        relative_offset = -((65536 / PLT_ENTRY_SIZE - 1) * PLT_ENTRY_SIZE) / 2;

    if (!bfd_link_pic(info)) {
        memcpy(plt->contents + iplt_offset, elf_s390_plt_entry, PLT_ENTRY_SIZE);
        bfd_put_32(output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
        bfd_put_32(output_bfd, gotplt->output_section->vma + got_offset, plt->contents + iplt_offset + 24);
    } else if (got_offset < 4096) {
        memcpy(plt->contents + iplt_offset, elf_s390_plt_pic12_entry, PLT_ENTRY_SIZE);
        bfd_put_16(output_bfd, 0xc000 | got_offset, plt->contents + iplt_offset + 2);
        bfd_put_32(output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
    } else if (got_offset < 32768) {
        memcpy(plt->contents + iplt_offset, elf_s390_plt_pic16_entry, PLT_ENTRY_SIZE);
        bfd_put_16(output_bfd, got_offset, plt->contents + iplt_offset + 2);
        bfd_put_32(output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
    } else {
        memcpy(plt->contents + iplt_offset, elf_s390_plt_pic_entry, PLT_ENTRY_SIZE);
        bfd_put_32(output_bfd, relative_offset << 16, plt->contents + iplt_offset + 20);
        bfd_put_32(output_bfd, got_offset, plt->contents + iplt_offset + 24);
    }

    bfd_put_32(output_bfd, relplt->output_offset + iplt_index * RELA_ENTRY_SIZE, plt->contents + iplt_offset + 28);
    bfd_put_32(output_bfd, plt->output_section->vma + plt->output_offset + iplt_offset + 12, gotplt->contents + igotiplt_offset);

    Elf_Internal_Rela rela;
    rela.r_offset = gotplt->output_section->vma + got_offset;

    if (!h || h->dynindx == -1 || ((bfd_link_executable(info) || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT) && h->def_regular)) {
        rela.r_info = ELF32_R_INFO(0, R_390_IRELATIVE);
        rela.r_addend = resolver_address;
    } else {
        rela.r_info = ELF32_R_INFO(h->dynindx, R_390_JMP_SLOT);
        rela.r_addend = 0;
    }

    bfd_elf32_swap_reloca_out(output_bfd, &rela, relplt->contents + iplt_index * RELA_ENTRY_SIZE);
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool elf_s390_finish_dynamic_symbol(
    bfd *output_bfd,
    struct bfd_link_info *info,
    struct elf_link_hash_entry *h,
    Elf_Internal_Sym *sym) {
  struct elf_s390_link_hash_table *htab = elf_s390_hash_table(info);
  struct elf_s390_link_hash_entry *eh = (struct elf_s390_link_hash_entry *)h;

  if (h->plt.offset == (bfd_vma)-1 && h->got.offset == (bfd_vma)-1) {
    if (h == htab->elf.hdynamic || h == htab->elf.hgot || h == htab->elf.hplt) {
      sym->st_shndx = SHN_ABS;
    }
    return true;
  }

  if (h->plt.offset != (bfd_vma)-1) {
    process_plt_entry(output_bfd, info, h, htab, eh, sym);
  }

  if (h->got.offset != (bfd_vma)-1) {
    process_got_entry(output_bfd, info, h, htab, sym);
  }

  if (h->needs_copy) {
    process_copy_reloc(output_bfd, h, htab);
  }

  if (h == htab->elf.hdynamic || h == htab->elf.hgot || h == htab->elf.hplt) {
    sym->st_shndx = SHN_ABS;
  }

  return true;
}

static void process_plt_entry(
    bfd *output_bfd,
    struct bfd_link_info *info,
    struct elf_link_hash_entry *h,
    struct elf_s390_link_hash_table *htab,
    struct elf_s390_link_hash_entry *eh,
    Elf_Internal_Sym *sym) {
  bfd_vma plt_index, got_offset, relative_offset;
  Elf_Internal_Rela rela;
  bfd_byte *loc;

  if (s390_is_ifunc_symbol_p(h) && h->def_regular) {
    elf_s390_finish_ifunc_symbol(output_bfd, info, h, htab, h->plt.offset,
        eh->ifunc_resolver_address +
        eh->ifunc_resolver_section->output_offset +
        eh->ifunc_resolver_section->output_section->vma);
  } else {
    if (h->dynindx == -1 || htab->elf.splt == NULL || htab->elf.sgotplt == NULL || htab->elf.srelplt == NULL) {
      abort();
    }
    plt_index = (h->plt.offset - PLT_FIRST_ENTRY_SIZE) / PLT_ENTRY_SIZE;
    got_offset = (plt_index + 3) * GOT_ENTRY_SIZE;
    relative_offset = adjust_relative_offset(PLT_FIRST_ENTRY_SIZE, PLT_ENTRY_SIZE, plt_index);

    setup_plt_entry(output_bfd, info, htab, h, plt_index, got_offset, relative_offset);

    bfd_put_32(output_bfd, plt_index * sizeof(Elf32_External_Rela),
        htab->elf.splt->contents + h->plt.offset + 28);

    bfd_put_32(output_bfd,
        (htab->elf.splt->output_section->vma
            + htab->elf.splt->output_offset
            + h->plt.offset
            + 12),
        htab->elf.sgotplt->contents + got_offset);

    setup_reloc_entry(output_bfd, htab, got_offset, h->dynindx, R_390_JMP_SLOT, plt_index, &rela);

    if (!h->def_regular) {
      sym->st_shndx = SHN_UNDEF;
    }
  }
}

static bfd_vma adjust_relative_offset(bfd_vma first_entry_size, bfd_vma entry_size, bfd_vma plt_index) {
  bfd_vma relative_offset = -(first_entry_size + (entry_size * plt_index) + 18) / 2;
  if (-relative_offset > 32768) {
    relative_offset = -(unsigned)(((65536 / entry_size - 1) * entry_size) / 2);
  }
  return relative_offset;
}

static void setup_plt_entry(
    bfd *output_bfd,
    struct bfd_link_info *info,
    struct elf_s390_link_hash_table *htab,
    struct elf_link_hash_entry *h,
    bfd_vma plt_index,
    bfd_vma got_offset,
    bfd_vma relative_offset) {
  if (!bfd_link_pic(info)) {
    init_plt_entry(htab, h->plt.offset, elf_s390_plt_entry, output_bfd);
    bfd_put_32(output_bfd, (bfd_vma)0 + (relative_offset << 16), 
        htab->elf.splt->contents + h->plt.offset + 20);
    bfd_put_32(output_bfd,
        (htab->elf.sgotplt->output_section->vma
            + htab->elf.sgotplt->output_offset
            + got_offset),
        htab->elf.splt->contents + h->plt.offset + 24);
  } else {
    adjust_pic_plt_entry(htab, h, plt_index, got_offset, relative_offset, output_bfd);
  }
}

static void adjust_pic_plt_entry(
    struct elf_s390_link_hash_table *htab,
    struct elf_link_hash_entry *h,
    bfd_vma plt_index,
    bfd_vma got_offset,
    bfd_vma relative_offset,
    bfd *output_bfd) {
  const unsigned char *plt_template;
  if (got_offset < 4096) {
    plt_template = elf_s390_plt_pic12_entry;
  } else if (got_offset < 32768) {
    plt_template = elf_s390_plt_pic16_entry;
  } else {
    plt_template = elf_s390_plt_pic_entry;
  }
  init_plt_entry(htab, h->plt.offset, plt_template, output_bfd);
  adjust_pic_got_offset(output_bfd, h, got_offset, plt_template, htab->elf.splt->contents);
  bfd_put_32(output_bfd, (bfd_vma)0 + (relative_offset << 16), htab->elf.splt->contents + h->plt.offset + 20);
}

static void adjust_pic_got_offset(bfd *output_bfd, struct elf_link_hash_entry *h, bfd_vma got_offset,
    const unsigned char *plt_template, bfd_byte *plt_contents) {
  if (plt_template == elf_s390_plt_pic12_entry) {
    bfd_put_16(output_bfd, (bfd_vma)0xc000 | got_offset, plt_contents + h->plt.offset + 2);
  } else if (plt_template == elf_s390_plt_pic16_entry) {
    bfd_put_16(output_bfd, (bfd_vma)got_offset, plt_contents + h->plt.offset + 2);
  }
}

static void init_plt_entry(
    struct elf_s390_link_hash_table *htab,
    bfd_vma plt_offset,
    const unsigned char *plt_template,
    bfd *output_bfd) {
  memcpy(htab->elf.splt->contents + plt_offset, plt_template, PLT_ENTRY_SIZE);
}

static void setup_reloc_entry(
    bfd *output_bfd,
    struct elf_s390_link_hash_table *htab,
    bfd_vma got_offset,
    int dynindx,
    unsigned int type,
    bfd_vma plt_index,
    Elf_Internal_Rela *rela) {
  
  bfd_byte *loc = htab->elf.srelplt->contents + plt_index * sizeof(Elf32_External_Rela);
  rela->r_offset = (htab->elf.sgotplt->output_section->vma
      + htab->elf.sgotplt->output_offset
      + got_offset);
  rela->r_info = ELF32_R_INFO(dynindx, type);
  rela->r_addend = 0;
  bfd_elf32_swap_reloca_out(output_bfd, rela, loc);
}

static void process_got_entry(
    bfd *output_bfd,
    struct bfd_link_info *info,
    struct elf_link_hash_entry *h,
    struct elf_s390_link_hash_table *htab,
    Elf_Internal_Sym *sym) {
  if ((elf_s390_hash_entry(h)->tls_type == GOT_TLS_GD ||
      elf_s390_hash_entry(h)->tls_type == GOT_TLS_IE ||
      elf_s390_hash_entry(h)->tls_type == GOT_TLS_IE_NLT) ||
      htab->elf.sgot == NULL ||
      htab->elf.srelgot == NULL) {
    return;
  }

  Elf_Internal_Rela rela;
  bfd_byte *loc;
  set_got_reloc_info(output_bfd, info, h, htab, &rela);

  loc = htab->elf.srelgot->contents + htab->elf.srelgot->reloc_count++ * sizeof(Elf32_External_Rela);
  bfd_elf32_swap_reloca_out(output_bfd, &rela, loc);
}

static void set_got_reloc_info(
    bfd *output_bfd,
    struct bfd_link_info *info,
    struct elf_link_hash_entry *h,
    struct elf_s390_link_hash_table *htab,
    Elf_Internal_Rela *rela) {

  rela->r_offset = (htab->elf.sgot->output_section->vma
      + htab->elf.sgot->output_offset
      + (h->got.offset & ~(bfd_vma)1));

  if (h->def_regular && s390_is_ifunc_symbol_p(h)) {
    if (bfd_link_pic(info)) {
      goto do_glob_dat;
    } else {
      bfd_put_32(output_bfd, (htab->elf.iplt->output_section->vma
          + htab->elf.iplt->output_offset
          + h->plt.offset),
          htab->elf.sgot->contents + h->got.offset);
      return;
    }
  } else if (SYMBOL_REFERENCES_LOCAL(info, h)) {
    if (UNDEFWEAK_NO_DYNAMIC_RELOC(info, h)) {
      return;
    }
    if (!h->def_regular && !ELF_COMMON_DEF_P(h)) {
      return;
    }
    BFD_ASSERT((h->got.offset & 1) != 0);
    rela->r_info = ELF32_R_INFO(0, R_390_RELATIVE);
    rela->r_addend = (h->root.u.def.value
        + h->root.u.def.section->output_section->vma
        + h->root.u.def.section->output_offset);
  } else {
    BFD_ASSERT((h->got.offset & 1) == 0);
  do_glob_dat:
    bfd_put_32(output_bfd, (bfd_vma)0, htab->elf.sgot->contents + h->got.offset);
    rela->r_info = ELF32_R_INFO(h->dynindx, R_390_GLOB_DAT);
    rela->r_addend = 0;
  }
}

static void process_copy_reloc(
    bfd *output_bfd,
    struct elf_link_hash_entry *h,
    struct elf_s390_link_hash_table *htab) {

  if (h->dynindx == -1 ||
      (h->root.type != bfd_link_hash_defined && h->root.type != bfd_link_hash_defweak) ||
      htab->elf.srelbss == NULL ||
      htab->elf.sreldynrelro == NULL) {
    abort();
  }

  Elf_Internal_Rela rela;
  asection *s;
  bfd_byte *loc;

  rela.r_offset = (h->root.u.def.value
      + h->root.u.def.section->output_section->vma
      + h->root.u.def.section->output_offset);
  rela.r_info = ELF32_R_INFO(h->dynindx, R_390_COPY);
  rela.r_addend = 0;

  if (h->root.u.def.section == htab->elf.sdynrelro) {
    s = htab->elf.sreldynrelro;
  } else {
    s = htab->elf.srelbss;
  }
  loc = s->contents + s->reloc_count++ * sizeof(Elf32_External_Rela);
  bfd_elf32_swap_reloca_out(output_bfd, &rela, loc);
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

#include <assert.h>

static enum elf_reloc_type_class elf_s390_reloc_type_class(const struct bfd_link_info *info, const asection *rel_sec, const Elf_Internal_Rela *rela) {
    assert(info != NULL);
    assert(rela != NULL);

    bfd *abfd = info->output_bfd;
    const struct elf_backend_data *bed = get_elf_backend_data(abfd);
    struct elf_s390_link_hash_table *htab = elf_s390_hash_table(info);
    unsigned long r_symndx = ELF32_R_SYM(rela->r_info);

    if (htab->elf.dynsym == NULL) {
        abort();
    }

    Elf_Internal_Sym sym;
    if (!bed->s->swap_symbol_in(abfd, (htab->elf.dynsym->contents + r_symndx * bed->s->sizeof_sym), 0, &sym)) {
        abort();
    }

    if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
        return reloc_class_ifunc;
    }

    int type = (int)ELF32_R_TYPE(rela->r_info);
    switch (type) {
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

static bool elf_s390_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info) {
    struct elf_s390_link_hash_table *htab = elf_s390_hash_table(info);
    bfd *dynobj = htab->elf.dynobj;
    asection *sdyn = bfd_get_linker_section(dynobj, ".dynamic");

    if (!sdyn || !htab->elf.sgot) {
        abort();
    }

    if (htab->elf.dynamic_sections_created) {
        Elf32_External_Dyn *dynptr = (Elf32_External_Dyn *)sdyn->contents;
        Elf32_External_Dyn *dynend = (Elf32_External_Dyn *)(sdyn->contents + sdyn->size);

        for (; dynptr < dynend; dynptr++) {
            Elf_Internal_Dyn dyn;
            asection *s = NULL;

            bfd_elf32_swap_dyn_in(dynobj, dynptr, &dyn);

            switch (dyn.d_tag) {
                case DT_PLTGOT:
                    s = htab->elf.sgotplt;
                    break;
                case DT_JMPREL:
                    s = htab->elf.srelplt;
                    break;
                case DT_PLTRELSZ:
                    dyn.d_un.d_val = htab->elf.srelplt->size;
                    if (htab->elf.irelplt) {
                        dyn.d_un.d_val += htab->elf.irelplt->size;
                    }
                    break;
                default:
                    continue;
            }

            if(s) {
                dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
            }

            bfd_elf32_swap_dyn_out(output_bfd, &dyn, dynptr);
        }

        if (htab->elf.splt && htab->elf.splt->size > 0) {
            memset(htab->elf.splt->contents, 0, PLT_FIRST_ENTRY_SIZE);

            if (bfd_link_pic(info)) {
                memcpy(htab->elf.splt->contents, elf_s390_plt_pic_first_entry, PLT_FIRST_ENTRY_SIZE);
            } else {
                memcpy(htab->elf.splt->contents, elf_s390_plt_first_entry, PLT_FIRST_ENTRY_SIZE);
                bfd_put_32(output_bfd, htab->elf.sgotplt->output_section->vma + htab->elf.sgotplt->output_offset, htab->elf.splt->contents + 24);
            }
            elf_section_data(htab->elf.splt->output_section)->this_hdr.sh_entsize = 4;
        }
    }

    if (htab->elf.sgotplt && htab->elf.sgotplt->size > 0) {
        bfd_vma sdyn_vma = sdyn ? sdyn->output_section->vma + sdyn->output_offset : 0;
        
        bfd_put_32(output_bfd, sdyn_vma, htab->elf.sgotplt->contents);
        bfd_put_32(output_bfd, 0, htab->elf.sgotplt->contents + 4);
        bfd_put_32(output_bfd, 0, htab->elf.sgotplt->contents + 8);

        elf_section_data(htab->elf.sgotplt->output_section)->this_hdr.sh_entsize = 4;
    }

    for (bfd *ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next) {
        if (!is_s390_elf(ibfd)) {
            continue;
        }

        struct plt_entry *local_plt = elf_s390_local_plt(ibfd);
        Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr(ibfd);

        if (local_plt) {
            for (unsigned int i = 0; i < symtab_hdr->sh_info; i++) {
                if (local_plt[i].plt.offset != (bfd_vma)-1) {
                    asection *sec = local_plt[i].sec;
                    Elf_Internal_Sym *isym = bfd_sym_from_r_symndx(&htab->elf.sym_cache, ibfd, i);

                    if (!isym) {
                        return false;
                    }

                    if (ELF_ST_TYPE(isym->st_info) == STT_GNU_IFUNC) {
                        elf_s390_finish_ifunc_symbol(output_bfd, info, NULL, htab, local_plt[i].plt.offset, isym->st_value + sec->output_section->vma + sec->output_offset);
                    }
                }
            }
        }
    }

    return true;
}

/* Support for core dump NOTE sections.  */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

static bool elf_s390_grok_prstatus(bfd *abfd, Elf_Internal_Note *note) {
    if (note->descsz != 224) {
        return false;
    }

    if (elf_tdata(abfd) == NULL || elf_tdata(abfd)->core == NULL) {
        return false;
    }

    elf_tdata(abfd)->core->signal = bfd_get_16(abfd, note->descdata + 12);
    elf_tdata(abfd)->core->lwpid = bfd_get_32(abfd, note->descdata + 24);
    
    unsigned int offset = 72;
    unsigned int size = 144;
    
    return _bfd_elfcore_make_pseudosection(abfd, ".reg", size, note->descpos + offset);
}

#include <stdbool.h>
#include <string.h>

static bool elf_s390_grok_psinfo(bfd *abfd, Elf_Internal_Note *note) {
    if (note->descsz != 124) {  // sizeof(struct elf_prpsinfo) on s390
        return false;
    }

    elf_internal_core *core_data = elf_tdata(abfd)->core;
    core_data->pid = bfd_get_32(abfd, note->descdata + 12);
    core_data->program = _bfd_elfcore_strndup(abfd, note->descdata + 28, 16);
    core_data->command = _bfd_elfcore_strndup(abfd, note->descdata + 44, 80);

    char *command = core_data->command;
    size_t n = strlen(command);

    if (n > 0 && command[n - 1] == ' ') {
        command[n - 1] = '\0';
    }

    return true;
}

static char *
elf_s390_write_core_note (bfd *abfd, char *buf, int *bufsiz,
                          int note_type, ...)
{
    va_list ap;
    char *result = NULL;

    va_start(ap, note_type);

    if (note_type == NT_PRPSINFO)
    {
        char data[124] = {0};
        const char *fname = va_arg(ap, const char *);
        const char *psargs = va_arg(ap, const char *);
        
        strncpy(data + 28, fname, 15);
        data[28 + 15] = '\0';  // Ensure null termination
        strncpy(data + 44, psargs, 79);
        data[44 + 79] = '\0';  // Ensure null termination

        result = elfcore_write_note(abfd, buf, bufsiz, "CORE", note_type, &data, sizeof(data));
    }
    else if (note_type == NT_PRSTATUS)
    {
        char data[224] = {0};
        long pid = va_arg(ap, long);
        int cursig = va_arg(ap, int);
        const void *gregs = va_arg(ap, const void *);

        bfd_put_16(abfd, cursig, data + 12);
        bfd_put_32(abfd, pid, data + 24);
        memcpy(data + 72, gregs, 144);

        result = elfcore_write_note(abfd, buf, bufsiz, "CORE", note_type, &data, sizeof(data));
    }

    va_end(ap);
    return result;
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma elf_s390_plt_sym_val(bfd_vma i, const asection *plt) {
  if (plt == NULL) {
    return 0; // Error handling: return 0 when plt is NULL
  }
  
  return plt->vma + PLT_FIRST_ENTRY_SIZE + i * PLT_ENTRY_SIZE;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

#include <stdbool.h>

static bool is_s390_elf(bfd *abfd);
static bool elf_s390_merge_obj_attributes(bfd *abfd, struct bfd_link_info *info);

static bool elf32_s390_merge_private_bfd_data(bfd *ibfd, struct bfd_link_info *info) {
    if (!is_s390_elf(ibfd) || !is_s390_elf(info->output_bfd)) {
        return true;
    }

    if (!elf_s390_merge_obj_attributes(ibfd, info)) {
        return false;
    }

    elf_elfheader(info->output_bfd)->e_flags |= elf_elfheader(ibfd)->e_flags;
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
