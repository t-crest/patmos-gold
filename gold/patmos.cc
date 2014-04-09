// patmos.cc -- patmos target support for gold.

// Copyright 2012 Free Software Foundation, Inc.
// Written by Florian Brandner <flbr@imm.dtu.dk>.

// This file is part of gold.

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
// MA 02110-1301, USA.

#include "gold.h"

#include "elfcpp.h"
#include "gc.h"
#include "object.h"
#include "output.h"
#include "patmos.h"
#include "reloc.h"
#include "symtab.h"
#include "target.h"
#include "target-reloc.h"
#include "target-select.h"

namespace
{
  using namespace gold;

  class Target_Patmos : public Sized_target<32, true>
  {
  public:
    typedef Output_data_reloc<elfcpp::SHT_REL, false, 32, true> Reloc_section;

    Target_Patmos()
      : Sized_target<32, true>(&patmos_info)
    {
    }

    // Process the relocs for a section, and record information of the
    // mapping from source to destination sections. This mapping is later
    // used to determine unreferenced garbage sections. This procedure is
    // only called during garbage collection.
    virtual void
    gc_process_relocs(Symbol_table* symtab,
                      Layout* layout,
                      Sized_relobj_file<32, true>* object,
                      unsigned int data_shndx,
                      unsigned int sh_type,
                      const unsigned char* prelocs,
                      size_t reloc_count,
                      Output_section* output_section,
                      bool needs_special_offset_handling,
                      size_t local_symbol_count,
                      const unsigned char* plocal_symbols);

    // Scan the relocs for a section, and record any information
    // required for the symbol.  SYMTAB is the symbol table.  OBJECT is
    // the object in which the section appears.  DATA_SHNDX is the
    // section index that these relocs apply to.  SH_TYPE is the type of
    // the relocation section, SHT_REL or SHT_RELA.  PRELOCS points to
    // the relocation data.  RELOC_COUNT is the number of relocs.
    // LOCAL_SYMBOL_COUNT is the number of local symbols.
    // OUTPUT_SECTION is the output section.
    // NEEDS_SPECIAL_OFFSET_HANDLING is true if offsets to the output
    // sections are not mapped as usual.  PLOCAL_SYMBOLS points to the
    // local symbol data from OBJECT.  GLOBAL_SYMBOLS is the array of
    // pointers to the global symbol table from OBJECT.
    virtual void
    scan_relocs(Symbol_table* symtab,
                Layout* layout,
                Sized_relobj_file<32, true>* object,
                unsigned int data_shndx,
                unsigned int sh_type,
                const unsigned char* prelocs,
                size_t reloc_count,
                Output_section* output_section,
                bool needs_special_offset_handling,
                size_t local_symbol_count,
                const unsigned char* plocal_symbols);

    // Relocate section data.  SH_TYPE is the type of the relocation
    // section, SHT_REL or SHT_RELA.  PRELOCS points to the relocation
    // information.  RELOC_COUNT is the number of relocs.
    // OUTPUT_SECTION is the output section.
    // NEEDS_SPECIAL_OFFSET_HANDLING is true if offsets must be mapped
    // to correspond to the output section.  VIEW is a view into the
    // output file holding the section contents, VIEW_ADDRESS is the
    // virtual address of the view, and VIEW_SIZE is the size of the
    // view.  If NEEDS_SPECIAL_OFFSET_HANDLING is true, the VIEW_xx
    // parameters refer to the complete output section data, not just
    // the input section data.
    virtual void
    relocate_section(const Relocate_info<32, true>*,
                    unsigned int sh_type,
                    const unsigned char* prelocs,
                    size_t reloc_count,
                    Output_section* output_section,
                    bool needs_special_offset_handling,
                    unsigned char* view,
                    elfcpp::Elf_types<32>::Elf_Addr view_address,
                    section_size_type view_size,
                    const Reloc_symbol_changes*);

    // Scan the relocs during a relocatable link.  The parameters are
    // like scan_relocs, with an additional Relocatable_relocs
    // parameter, used to record the disposition of the relocs.
    virtual void
    scan_relocatable_relocs(Symbol_table* symtab,
                            Layout* layout,
                            Sized_relobj_file<32, true>* object,
                            unsigned int data_shndx,
                            unsigned int sh_type,
                            const unsigned char* prelocs,
                            size_t reloc_count,
                            Output_section* output_section,
                            bool needs_special_offset_handling,
                            size_t local_symbol_count,
                            const unsigned char* plocal_symbols,
                            Relocatable_relocs*);

    // Relocate a section during a relocatable link.  The parameters are
    // like relocate_section, with additional parameters for the view of
    // the output reloc section.
    virtual void
    relocate_relocs(const Relocate_info<32, true>*,
                    unsigned int sh_type,
                    const unsigned char* prelocs,
                    size_t reloc_count,
                    Output_section* output_section,
                    elfcpp::Elf_types<32>::Elf_Off 
                      offset_in_output_section,
                    const Relocatable_relocs*,
                    unsigned char* view,
                    elfcpp::Elf_types<32>::Elf_Addr view_address,
                    section_size_type view_size,
                    unsigned char* reloc_view,
                    section_size_type reloc_view_size);

    // Return a string used to fill a code section with nops.
    virtual std::string
    do_code_fill(section_size_type length) const;

    /// check if the symbol is a function, if so, store its start address and
    /// size.
    void append_function(const Sized_symbol<32> *);

    /// retrieve information computed during the scan for a FREL relocation.
    elfcpp::Elf_types<32>::Elf_Addr get_frel_address(
                                               const elfcpp::Rel<32, true>& rel,
                                               unsigned int data_shndx);
  private:
    // Information about this specific target which we pass to the
    // general Target structure.
    static const Target::Target_info patmos_info;

    /// list of function start addresses and sizes.
    typedef std::vector<std::pair<elfcpp::Elf_types<32>::Elf_Addr,
                           elfcpp::Elf_types<32>::Elf_Addr> > func_start_size_t;

    /// list of currently known functions
    // FIXME: this is shared state, and might be unsafe.
    func_start_size_t Functions;

    /// map of FREL relocations/data_shndx to a value
    typedef std::map<std::pair<elfcpp::Elf_types<32>::Elf_Addr, unsigned int>,
                               elfcpp::Elf_types<32>::Elf_Addr> frel_info_t;

    // FIXME: this is shared state, and might be unsafe.
    frel_info_t FRELInfo;

    func_start_size_t::const_iterator find_covering_function_or_code(
                                           section_size_type lsym_offset) const;

    // The class which scans relocations.

    class Scan
    {
    public:
      Scan()
      { }

      static inline int
      get_reference_flags(unsigned int r_type);

      inline void
      local(Symbol_table* symtab, Layout* layout, Target_Patmos* target,
            Sized_relobj_file<32, true>* object,
            unsigned int data_shndx,
            Output_section* output_section,
            const elfcpp::Rel<32, true>& reloc, unsigned int r_type,
            const elfcpp::Sym<32, true>& lsym, bool is_discarded);

      inline void
      global(Symbol_table* symtab, Layout* layout, Target_Patmos* target,
            Sized_relobj_file<32, true>* object,
            unsigned int data_shndx,
            Output_section* output_section,
            const elfcpp::Rel<32, true>& reloc, unsigned int r_type,
            Symbol* gsym);

      inline bool
      local_reloc_may_be_function_pointer(Symbol_table* , Layout* ,
                                          Target_Patmos* ,
                                          Sized_relobj_file<32, true>* ,
                                          unsigned int ,
                                          Output_section* ,
                                          const elfcpp::Rel<32, true>& ,
                                          unsigned int ,
                                          const elfcpp::Sym<32, true>&)
      { return false; }

      inline bool
      global_reloc_may_be_function_pointer(Symbol_table* , Layout* ,
                                          Target_Patmos* ,
                                          Sized_relobj_file<32, true>* ,
                                          unsigned int ,
                                          Output_section* ,
                                          const elfcpp::Rel<32, true>& ,
                                          unsigned int , Symbol*)
      { return false; }
    private:
      static void
      unsupported_reloc_local(Sized_relobj_file<32, true>*,
                              unsigned int r_type);

      static void
      unsupported_reloc_global(Sized_relobj_file<32, true>*,
                              unsigned int r_type, Symbol*);
    };

    // The class which implements relocation.
    class Relocate
    {
    public:
      // Do a relocation.  Return false if the caller should not issue
      // any warnings about this relocation.
      inline bool
      relocate(const Relocate_info<32, true>*, Target_Patmos*,
              Output_section*, size_t relnum,
              const elfcpp::Rel<32, true>&,
              unsigned int r_type, const Sized_symbol<32>*,
              const Symbol_value<32>*,
              unsigned char*,
              elfcpp::Elf_types<32>::Elf_Addr,
              section_size_type);
    };

    // A class which returns the size required for a relocation type,
    // used while scanning relocs during a relocatable link.
    class Relocatable_size_for_reloc
    {
    public:
      unsigned int
      get_size_for_reloc(unsigned int, Relobj*);
    };
  };

  const Target::Target_info Target_Patmos::patmos_info =
  {
    32,                   // size
    true,                 // is_big_endian
    elfcpp::EM_PATMOS,    // machine_code
    false,                // has_make_symbol
    false,                // has_resolve
    true,                 // has_code_fill
    true,                 // is_default_stack_executable
    true,                 // can_icf_inline_merge_sections
    '\0',                 // wrap_char
    "",                   // dynamic_linker
    0x00001000,           // default_text_segment_address
    0x1000,               // abi_pagesize (overridable by -z max-page-size)
    0x1000,               // common_pagesize (overridable by -z common-page-size)
    false,                // isolate_execinstr
    0,                    // rosegment_gap
    elfcpp::SHN_UNDEF,    // small_common_shndx
    elfcpp::SHN_UNDEF,    // large_common_shndx
    0,                    // small_common_section_flags
    0,                    // large_common_section_flags
    NULL,                 // attributes_section
    NULL,                 // attributes_vendor
    "_start"              // entry_symbol_name
  };
  
  class Patmos_relocate_functions
  {
  private:
    /// patch - patch data/instruction according to a relocation.
    /// @param view bytes of the data/instruction to be relocated.
    /// @param dst_mask a mask applied before patching the relocation.
    /// @param object the current object file
    /// @param psymval symbol to retrieve the address to patch the relocation
    /// @param shr shift the symbols'address to the right (optional)
    static inline void
    patch(unsigned char* view,
          elfcpp::Elf_Xword dst_mask,
          const Sized_relobj_file<32, true>* object,
          const Symbol_value<32>* psymval,
          unsigned int shr = 0)
    {
      typedef elfcpp::Swap<32, true>::Valtype Valtype;

      // get a pointer to the data/instruction bytes to be patched
      Valtype* wv = reinterpret_cast<Valtype*>(view);

      // read the original value using the pointer
      Valtype val = elfcpp::Swap<32, true>::readval(wv);

      // compute the address used for the patching (including shifting)
      Valtype reloc = psymval->value(object, 0) >> shr;

      // apply the mask.
      gold_assert((val & dst_mask) == 0);
      val &= ~dst_mask;
      reloc &= dst_mask;

      // rewrite the patched value
      elfcpp::Swap<32, true>::writeval(wv, val | reloc);
    }

    /// patch - patch data/instruction according to a relocation, assuming a 
    /// non-zero addend.
    /// @param view bytes of the data/instruction to be relocated.
    /// @param dst_mask a mask applied before patching the relocation.
    /// @param object the current object file
    /// @param psymval symbol to retrieve the address to patch the relocation
    /// @param shr shift the symbols'address to the right (optional)
    static inline void
    patch_withaddend(unsigned char* view,
                     elfcpp::Elf_Xword dst_mask,
                     const Sized_relobj_file<32, true>* object,
                     const Symbol_value<32>* psymval,
                     unsigned int shr = 0)
    {
      typedef elfcpp::Swap<32, true>::Valtype Valtype;

      // get a pointer to the data/instruction bytes to be patched
      Valtype* wv = reinterpret_cast<Valtype*>(view);

      // read the original value using the pointer
      Valtype val = elfcpp::Swap<32, true>::readval(wv);

      // compute the addend
      Valtype addend = (val & dst_mask);

      // compute the address used for the patching (including shifting)
      Valtype reloc = (psymval->value(object, 0) >> shr) + addend;

      // apply the mask.
      val &= ~dst_mask;
      reloc &= dst_mask;

      // rewrite the patched value
      elfcpp::Swap<32, true>::writeval(wv, val | reloc);
    }

    /// patch - patch data/instruction according to a relocation.
    /// @param view bytes of the data/instruction to be relocated.
    /// @param dst_mask a mask applied before patching the relocation.
    /// @param object the current object file
    /// @param address the address to patch
    /// @param shr shift the symbols'address to the right (optional)
    static inline void
    patch(unsigned char* view,
          elfcpp::Elf_Xword dst_mask,
          elfcpp::Elf_Xword address,
          unsigned int shr = 0)
    {
      typedef elfcpp::Swap<32, true>::Valtype Valtype;

      // get a pointer to the data/instruction bytes to be patched
      Valtype* wv = reinterpret_cast<Valtype*>(view);

      // read the original value using the pointer
      Valtype val = elfcpp::Swap<32, true>::readval(wv);

      // compute the address used for the patching (including shifting)
      Valtype reloc = address >> shr;

      // apply the mask.
      gold_assert((val & dst_mask) == 0);
      val &= ~dst_mask;
      reloc &= dst_mask;

      // rewrite the patched value
      elfcpp::Swap<32, true>::writeval(wv, val | reloc);
    }

    /// patch - patch data/instruction according to a relocation, assuming a 
    /// non-zero addend.
    /// @param view bytes of the data/instruction to be relocated.
    /// @param dst_mask a mask applied before patching the relocation.
    /// @param object the current object file
    /// @param address the address to patch
    /// @param shr shift the symbols'address to the right (optional)
    static inline void
    patch_withaddend(unsigned char* view,
                     elfcpp::Elf_Xword dst_mask,
                     elfcpp::Elf_Xword address,
                     unsigned int shr = 0)
    {
      typedef elfcpp::Swap<32, true>::Valtype Valtype;

      // get a pointer to the data/instruction bytes to be patched
      Valtype* wv = reinterpret_cast<Valtype*>(view);

      // read the original value using the pointer
      Valtype val = elfcpp::Swap<32, true>::readval(wv);

      // compute the addend
      Valtype addend = (val & dst_mask);

      // compute the address used for the patching (including shifting)
      Valtype reloc = (address >> shr) + addend;

      // apply the mask.
      val &= ~dst_mask;
      reloc &= dst_mask;

      // rewrite the patched value
      elfcpp::Swap<32, true>::writeval(wv, val | reloc);
    }
  public:
    /// cflb_abs - patch an instruction of the CFLb format using 22 bits of
    /// the absolute address.
    static inline void
    cflb_abs(unsigned char* view,
             const Sized_relobj_file<32, true> *object,
             const Symbol_value<32>* psymval)
    { patch(view, 0x3FFFFF, object, psymval, 2); }

    /// cflb_frel - patch an instruction of the CFLb format using 22 bits
    /// relative to the current function's base address.
    static inline void
    cflb_frel(unsigned char* view,
              elfcpp::Elf_Xword address)
    {  patch(view, 0x3FFFFF, address, 2); }

    /// cflb_pcrel - patch an instruction of the CFLb format using 22 bits
    /// relative to the current instruction address.
    static inline void
    cflb_pcrel(unsigned char* view,
              const Sized_relobj_file<32, true> *object,
              const Symbol_value<32>* psymval,
	      elfcpp::Elf_types<32>::Elf_Addr address)
    {  
      elfcpp::Elf_Xword reloc = (psymval->value(object, 0) - address);
      patch(view, 0x3FFFFF, reloc, 2); 
    }


    /// alui_abs - patch an instruction of the ALUi format using 12 bits of
    /// the absolute address.
    static inline void
    alui_abs(unsigned char* view,
             const Sized_relobj_file<32, true> *object,
             const Symbol_value<32>* psymval)
    { patch(view, 0xFFF, object, psymval); }

    /// alui_frel - patch an instruction of the ALUi format using 12 bits
    /// relative to the current function's base address.
    static inline void
    alui_frel(unsigned char* view,
              elfcpp::Elf_Xword address)
    {  patch(view, 0xFFF, address); }

    /// alul_abs - patch an instruction of the ALUl format using all 32 bits of
    /// the  absolute address.
    static inline void
    alul_abs(unsigned char* view,
             const Sized_relobj_file<32, true> *object,
             const Symbol_value<32>* psymval)
    { patch(view + 4, 0xFFFFFFFF, object, psymval); }

    /// alul_frel - patch an instruction of the ALUl format using all 32 bits
    /// relative to the current function's base address.
    static inline void
    alul_frel(unsigned char* view,
              elfcpp::Elf_Xword address)
    { patch(view + 4, 0xFFFFFFFF, address); }

    /// mem_abs - patch a memory load/store instruction of the LDT/STT format
    /// using 7 bits of the absolute address.
    static inline void
    mem_abs(unsigned char* view,
            const Sized_relobj_file<32, true> *object,
            const Symbol_value<32>* psymval,
            unsigned int shr  = 0)
    { patch(view, 0x7F, object, psymval, shr); }

    /// abs - patch a 32-bit data field using the absolute address.
    static inline void
    abs(unsigned char* view,
        const Sized_relobj_file<32, true> *object,
        const Symbol_value<32>* psymval)
    {
      patch_withaddend(view, 0xffffffff, object, psymval);
    }

    /// frel - patch a 32-bit data field using the address relative to the 
    /// current function's base.
    static inline void
    frel(unsigned char* view,
         elfcpp::Elf_Xword address)
    {
      patch_withaddend(view, 0xffffffff, address);
    }
  };

  // Get the Reference_flags for a particular relocation.

  int
  Target_Patmos::Scan::get_reference_flags(unsigned int r_type)
  {
    switch (r_type)
      {
      case elfcpp::R_PATMOS_NONE:
        // No symbol reference.
        return 0;
      case elfcpp::R_PATMOS_CFLB_ABS:
      case elfcpp::R_PATMOS_ALUI_ABS:
      case elfcpp::R_PATMOS_ALUL_ABS:
      case elfcpp::R_PATMOS_MEMB_ABS:
      case elfcpp::R_PATMOS_MEMH_ABS:
      case elfcpp::R_PATMOS_MEMW_ABS:
      case elfcpp::R_PATMOS_ABS_32:
        return Symbol::ABSOLUTE_REF;
      case elfcpp::R_PATMOS_CFLB_FREL:
      case elfcpp::R_PATMOS_CFLB_PCREL:
      case elfcpp::R_PATMOS_ALUI_FREL:
      case elfcpp::R_PATMOS_ALUL_FREL:
      case elfcpp::R_PATMOS_FREL_32:
        return Symbol::RELATIVE_REF;

      default:
        // Not expected.  We will give an error later.
        return 0;
      }
  }

  // Report an unsupported relocation against a local symbol.

  void
  Target_Patmos::Scan::unsupported_reloc_local(
                                            Sized_relobj_file<32, true>* object,
                                            unsigned int r_type)
  {
    gold_error(_("%s: unsupported reloc %u against local symbol"),
               object->name().c_str(), r_type);
  }

  // Scan a relocation for a local symbol.

  inline Target_Patmos::func_start_size_t::const_iterator
  Target_Patmos::find_covering_function_or_code(
                                            section_size_type lsym_offset) const
  {
    func_start_size_t::const_iterator found(Functions.end());
    for(func_start_size_t::const_iterator i(Functions.begin()),
        ie(Functions.end()); i != ie; i++)
    {
      // the label might be covered by a @function or @code region,
      // take the smaller one, i.e., the @code.
      if (i->first <= lsym_offset && lsym_offset <= i->first + i->second &&
          (found == ie || found->first <= i->first))
      {
        found = i;
      }
    }

    gold_assert(found != Functions.end());

    return found;
  }

  
  inline void
  Target_Patmos::Scan::local(
                             Symbol_table* symtab __attribute__((unused)),
                             Layout* layout __attribute__((unused)),
                             Target_Patmos* target,
                             Sized_relobj_file<32, true>* object,
                             unsigned int data_shndx,
                             Output_section* output_section __attribute__((unused)),
                             const elfcpp::Rel<32, true>& reloc,
                             unsigned int r_type,
                             const elfcpp::Sym<32, true>& lsym, 
                             bool is_discarded)
  {
    if (is_discarded) 
      return;
    
    bool is_CFLB = false;
    switch (r_type)
      {
      case elfcpp::R_PATMOS_NONE:
        break;

      case elfcpp::R_PATMOS_CFLB_ABS:
      case elfcpp::R_PATMOS_ALUI_ABS:
      case elfcpp::R_PATMOS_ALUL_ABS:
      case elfcpp::R_PATMOS_MEMB_ABS:
      case elfcpp::R_PATMOS_MEMH_ABS:
      case elfcpp::R_PATMOS_MEMW_ABS:
      case elfcpp::R_PATMOS_ABS_32:
        break;
      
      case elfcpp::R_PATMOS_CFLB_PCREL:
	break;
	
      case elfcpp::R_PATMOS_CFLB_FREL:
        is_CFLB = true;
      case elfcpp::R_PATMOS_ALUI_FREL:
      case elfcpp::R_PATMOS_ALUL_FREL:
      case elfcpp::R_PATMOS_FREL_32:
      {
        section_size_type lsym_offset =
                              convert_to_section_size_type(lsym.get_st_value());

        func_start_size_t::const_iterator lsym_cover(
                           target->find_covering_function_or_code(lsym_offset));

        // keep info on this relocation around for the patching later
        if (is_CFLB && (reloc.get_r_offset() < lsym_cover->first ||
               lsym_cover->first + lsym_cover->second < reloc.get_r_offset())) {
          // crossing from one code region into another, e.g., using a b
          // instruction
          gold_assert(lsym_offset == lsym_cover->first);

          // find the current code region
          func_start_size_t::const_iterator rel_cover(
                  target->find_covering_function_or_code(reloc.get_r_offset()));

          target->FRELInfo.insert(std::make_pair(
                                    std::make_pair(reloc.get_r_offset(),
                                                  data_shndx),
                                    (lsym_offset - rel_cover->first)));
        }
        else {
          // we stay within the same code region, e.g., using a bc
          // instruction.
          target->FRELInfo.insert(std::make_pair(
                                    std::make_pair(reloc.get_r_offset(),
                                                  data_shndx),
                                    (lsym_offset - lsym_cover->first)));
        }

        break;
      }

      default:
        unsupported_reloc_local(object, r_type);
        break;
      }
  }

  // Report an unsupported relocation against a global symbol.

  void
  Target_Patmos::Scan::unsupported_reloc_global(
                                            Sized_relobj_file<32, true>* object,
                                            unsigned int r_type,
                                            Symbol* gsym)
  {
    gold_error(_("%s: unsupported reloc %u against global symbol %s"),
              object->name().c_str(), r_type, gsym->demangled_name().c_str());
  }

  // Scan a relocation for a global symbol.

  inline void
  Target_Patmos::Scan::global(
                              Symbol_table* symtab __attribute__((unused)),
                              Layout* layout __attribute__((unused)),
                              Target_Patmos* target __attribute__((unused)),
                              Sized_relobj_file<32, true>* object,
                              unsigned int data_shndx __attribute__((unused)),
                              Output_section* output_section __attribute__((unused)),
                              const elfcpp::Rel<32, true>& reloc __attribute__((unused)),
                              unsigned int r_type,
                              Symbol* gsym)
  {
    switch (r_type)
      {
      case elfcpp::R_PATMOS_NONE:
        break;

      case elfcpp::R_PATMOS_CFLB_ABS:
      case elfcpp::R_PATMOS_ALUI_ABS:
      case elfcpp::R_PATMOS_ALUL_ABS:
      case elfcpp::R_PATMOS_MEMB_ABS:
      case elfcpp::R_PATMOS_MEMH_ABS:
      case elfcpp::R_PATMOS_MEMW_ABS:
      case elfcpp::R_PATMOS_ABS_32:
        break;

      case elfcpp::R_PATMOS_CFLB_PCREL:
	break;
	
      case elfcpp::R_PATMOS_CFLB_FREL:
      case elfcpp::R_PATMOS_ALUI_FREL:
      case elfcpp::R_PATMOS_ALUL_FREL:
      case elfcpp::R_PATMOS_FREL_32:
        // TODO: implement
        gold_assert(false && "Support for global FREL relocations missing.");
        break;

      default:
        unsupported_reloc_global(object, r_type, gsym);
        break;
      }
  }

  // Process relocations for gc.

  void
  Target_Patmos::gc_process_relocs(
                          Symbol_table* symtab,
                          Layout* layout,
                          Sized_relobj_file<32, true>* object,
                          unsigned int data_shndx,
                          unsigned int,
                          const unsigned char* prelocs,
                          size_t reloc_count,
                          Output_section* output_section,
                          bool needs_special_offset_handling,
                          size_t local_symbol_count,
                          const unsigned char* plocal_symbols)
  {
    gold::gc_process_relocs<32, true, Target_Patmos, elfcpp::SHT_REL,
                            Target_Patmos::Scan,
                            Target_Patmos::Relocatable_size_for_reloc>(
      symtab,
      layout,
      this,
      object,
      data_shndx,
      prelocs,
      reloc_count,
      output_section,
      needs_special_offset_handling,
      local_symbol_count,
      plocal_symbols);
  }

  // Scan relocations for a section.

  void
  Target_Patmos::scan_relocs(
                          Symbol_table* symtab,
                          Layout* layout,
                          Sized_relobj_file<32, true>* object,
                          unsigned int data_shndx,
                          unsigned int sh_type,
                          const unsigned char* prelocs,
                          size_t reloc_count,
                          Output_section* output_section,
                          bool needs_special_offset_handling,
                          size_t local_symbol_count,
                          const unsigned char* plocal_symbols)
  {
    if (sh_type == elfcpp::SHT_RELA)
      {
        gold_error(_("%s: unsupported RELA reloc section"),
                  object->name().c_str());
        return;
      }

    // find all global functions
    Functions.clear();
    symtab->for_all_symbols<32>(std::bind1st(
                                  std::mem_fun(&Target_Patmos::append_function),
                                  this));

    // find all local functions
    const int sym_size = elfcpp::Elf_sizes<32>::sym_size;
    for(size_t i = 0; i < local_symbol_count; i++)
    {
      elfcpp::Sym<32, true> lsym(plocal_symbols + i * sym_size);
      if (lsym.get_st_type() == elfcpp::STT_FUNC ||
          lsym.get_st_type() == elfcpp::STT_CODE)
      {
        section_offset_type value = convert_to_section_size_type(lsym.get_st_value());
        section_size_type fnsize = convert_to_section_size_type(lsym.get_st_size());
        Functions.push_back(std::make_pair(value, fnsize));
      }
    }

    gold::scan_relocs<32, true, Target_Patmos, elfcpp::SHT_REL,
                      Target_Patmos::Scan>(
      symtab,
      layout,
      this,
      object,
      data_shndx,
      prelocs,
      reloc_count,
      output_section,
      needs_special_offset_handling,
      local_symbol_count,
      plocal_symbols);
  }

  // Perform a relocation.

  elfcpp::Elf_types<32>::Elf_Addr
  Target_Patmos::get_frel_address(const elfcpp::Rel<32, true>& rel,
                                  unsigned int data_shndx)
  {
    Target_Patmos::frel_info_t::const_iterator i(
                 FRELInfo.find(std::make_pair(rel.get_r_offset(), data_shndx)));

    gold_assert(i != FRELInfo.end());

    return i->second;
  }

  inline bool
  Target_Patmos::Relocate::relocate(
                          const Relocate_info<32, true>* relinfo,
                          Target_Patmos* target,
                          Output_section*,
                          size_t relnum,
                          const elfcpp::Rel<32, true>& rel,
                          unsigned int r_type,
                          const Sized_symbol<32>* gsym __attribute__((unused)),
                          const Symbol_value<32>* psymval,
                          unsigned char* view,
                          elfcpp::Elf_types<32>::Elf_Addr address,
                          section_size_type view_size __attribute__((unused)))
  {
    typedef Patmos_relocate_functions Reloc;

    const Sized_relobj_file<32, true>* object = relinfo->object;

    switch (r_type)
      {
      case elfcpp::R_PATMOS_NONE:
        break;

      case elfcpp::R_PATMOS_CFLB_ABS:
        Reloc::cflb_abs(view, object, psymval);
        break;
      case elfcpp::R_PATMOS_CFLB_FREL:
        Reloc::cflb_frel(view, target->get_frel_address(rel,
                                                        relinfo->data_shndx));
        break;
      case elfcpp::R_PATMOS_ALUI_ABS:
        Reloc::alui_abs(view, object, psymval);
        break;
      case elfcpp::R_PATMOS_ALUI_FREL:
        Reloc::alui_frel(view, target->get_frel_address(rel,
                                                        relinfo->data_shndx));
        break;
      case elfcpp::R_PATMOS_ALUL_ABS:
        Reloc::alul_abs(view, object, psymval);
        break;
      case elfcpp::R_PATMOS_ALUL_FREL:
        Reloc::alul_frel(view, target->get_frel_address(rel,
                                                        relinfo->data_shndx));
        break;
      case elfcpp::R_PATMOS_MEMB_ABS:
        Reloc::mem_abs(view, object, psymval);
        break;
      case elfcpp::R_PATMOS_MEMH_ABS:
        Reloc::mem_abs(view, object, psymval, 1);
        break;
      case elfcpp::R_PATMOS_MEMW_ABS:
        Reloc::mem_abs(view, object, psymval, 2);
        break;
      case elfcpp::R_PATMOS_ABS_32:
        Reloc::abs(view, object, psymval);
        break;
      case elfcpp::R_PATMOS_FREL_32:
        Reloc::frel(view, target->get_frel_address(rel, relinfo->data_shndx));
        break;
      case elfcpp::R_PATMOS_CFLB_PCREL:
	Reloc::cflb_pcrel(view, object, psymval, address);
	break;
      default:
        gold_error_at_location(relinfo, relnum, rel.get_r_offset(),
                              _("unsupported reloc %u"),
                              r_type);
        break;
      }

    return true;
  }

  // Relocate section data.

  void
  Target_Patmos::relocate_section(
                          const Relocate_info<32, true>* relinfo,
                          unsigned int sh_type,
                          const unsigned char* prelocs,
                          size_t reloc_count,
                          Output_section* output_section,
                          bool needs_special_offset_handling,
                          unsigned char* view,
                          elfcpp::Elf_types<32>::Elf_Addr address,
                          section_size_type view_size,
                          const Reloc_symbol_changes* reloc_symbol_changes)
  {
    gold_assert(sh_type == elfcpp::SHT_REL);

    gold::relocate_section<32, true, Target_Patmos, elfcpp::SHT_REL,
      Target_Patmos::Relocate, gold::Default_comdat_behavior>(
      relinfo,
      this,
      prelocs,
      reloc_count,
      output_section,
      needs_special_offset_handling,
      view,
      address,
      view_size,
      reloc_symbol_changes);
  }

  // Return the size of a relocation while scanning during a relocatable
  // link.

  unsigned int
  Target_Patmos::Relocatable_size_for_reloc::get_size_for_reloc(
      unsigned int,
      Relobj*)
  {
    // seems we never get here? ;-)
    gold_unreachable();
    return 0;
  }

  // Scan the relocs during a relocatable link.

  void
  Target_Patmos::scan_relocatable_relocs(
                          Symbol_table* symtab,
                          Layout* layout,
                          Sized_relobj_file<32, true>* object,
                          unsigned int data_shndx,
                          unsigned int sh_type,
                          const unsigned char* prelocs,
                          size_t reloc_count,
                          Output_section* output_section,
                          bool needs_special_offset_handling,
                          size_t local_symbol_count,
                          const unsigned char* plocal_symbols,
                          Relocatable_relocs* rr)
  {
    gold_assert(sh_type == elfcpp::SHT_REL);

    typedef gold::Default_scan_relocatable_relocs<elfcpp::SHT_REL,
      Relocatable_size_for_reloc> Scan_relocatable_relocs;

    gold::scan_relocatable_relocs<32, true, elfcpp::SHT_REL,
        Scan_relocatable_relocs>(
      symtab,
      layout,
      object,
      data_shndx,
      prelocs,
      reloc_count,
      output_section,
      needs_special_offset_handling,
      local_symbol_count,
      plocal_symbols,
      rr);
  }

  // Relocate a section during a relocatable link.

  void
  Target_Patmos::relocate_relocs(
      const Relocate_info<32, true>* relinfo,
      unsigned int sh_type,
      const unsigned char* prelocs,
      size_t reloc_count,
      Output_section* output_section,
      elfcpp::Elf_types<32>::Elf_Off offset_in_output_section,
      const Relocatable_relocs* rr,
      unsigned char* view,
      elfcpp::Elf_types<32>::Elf_Addr view_address,
      section_size_type view_size,
      unsigned char* reloc_view,
      section_size_type reloc_view_size)
  {
    gold_assert(sh_type == elfcpp::SHT_REL);

    gold::relocate_relocs<32, true, elfcpp::SHT_REL>(
      relinfo,
      prelocs,
      reloc_count,
      output_section,
      offset_in_output_section,
      rr,
      view,
      view_address,
      view_size,
      reloc_view,
      reloc_view_size);
  }

  std::string
  Target_Patmos::do_code_fill(section_size_type length) const
  {
    // TODO this decodes into a valid NOP instruction, but
    //      it would be nicer to emit the usual NOP code.
    return std::string(length, static_cast<char>(0x00));
  }

  void
  Target_Patmos::append_function(const Sized_symbol<32> *sym)
  {
    if (sym->is_func() || sym->type() == elfcpp::STT_CODE)
    {
      Functions.push_back(std::make_pair(sym->value(), sym->symsize()));
    }
  }

  // The selector for Patmos object files.

  class Target_selector_patmos : public Target_selector
  {
  public:
    Target_selector_patmos()
      : Target_selector(elfcpp::EM_NONE, 32, true, "elf32-patmos", "")
    { }

    Target* do_recognize(int machine, int, int)
    {
      if (machine != elfcpp::EM_PATMOS)
        return NULL;
      else
        return this->instantiate_target();
    }

    Target* do_instantiate_target()
    { return new Target_Patmos(); }
  };

  Target_selector_patmos target_selector_patmos;
}

