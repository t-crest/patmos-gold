// patmos.h -- ELF definitions specific to EM_PATMOS -*- C++ -*-

// Copyright 2012 Free Software Foundation, Inc.
// Written by Florian Brandner <flbr@imm.dtu.dk>.

// This file is part of elfcpp.

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public License
// as published by the Free Software Foundation; either version 2, or
// (at your option) any later version.

// In addition to the permissions in the GNU Library General Public
// License, the Free Software Foundation gives you unlimited
// permission to link the compiled version of this file into
// combinations with other programs, and to distribute those
// combinations without any restriction coming from the use of this
// file.  (The Library Public License restrictions do apply in other
// respects; for example, they cover modification of the file, and
// distribution when not linked into a combined executable.)

// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Library General Public License for more details.

// You should have received a copy of the GNU Library General Public
// License along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
// 02110-1301, USA.

#ifndef ELFCPP_PATMOS_H
#define ELFCPP_PATMOS_H

namespace elfcpp
{

// The relocation numbers for patmos.
enum
{
  R_PATMOS_NONE       = 0,
  R_PATMOS_CFLB_ABS   = 1,
  R_PATMOS_CFLB_PCREL = 2,
  R_PATMOS_ALUI_ABS   = 3,
  R_PATMOS_ALUI_PCREL = 4,
  R_PATMOS_ALUL_ABS   = 5,
  R_PATMOS_ALUL_PCREL = 6,
  R_PATMOS_MEMB_ABS   = 7,
  R_PATMOS_MEMH_ABS   = 8,
  R_PATMOS_MEMW_ABS   = 9,
  R_PATMOS_ABS_32     = 10,
  R_PATMOS_PCREL_32   = 11
};

} // End namespace elfcpp.

#endif // !defined(ELFCPP_PATMOS_H)
