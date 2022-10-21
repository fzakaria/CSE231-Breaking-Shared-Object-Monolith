#include <link.h>

__attribute__((constructor)) static void init() {
  // Note: Cannot use print here.
}

/**
 * @brief Many of the comments here are copied verbatim from
 * https://github.com/buildsi/ldaudit-yaml as they are *excellent*.
 * It was an amazing learning resource to build an LD_AUDIT library.
 */

/*
   unsigned int la_version(unsigned int version);
   This is the only function that must be defined by an auditing
   library: it performs the initial handshake between the dynamic
   linker and the auditing library.  When invoking this function,
   the dynamic linker passes, in version, the highest version of the
   auditing interface that the linker supports.
   A typical implementation of this function simply returns the
   constant LAV_CURRENT, which indicates the version of <link.h>
   that was used to build the audit module.  If the dynamic linker
   does not support this version of the audit interface, it will
   refuse to activate this audit module.  If the function returns
   zero, the dynamic linker also does not activate this audit
   module.
   In order to enable backwards compatibility with older dynamic
   linkers, an audit module can examine the version argument and
   return an earlier version than LAV_CURRENT, assuming the module
   can adjust its implementation to match the requirements of the
   previous version of the audit interface.  The la_version function
   should not return the value of version without further checks
   because it could correspond to an interface that does not match
   the <link.h> definitions used to build the audit module.
*/
unsigned int la_version(unsigned int version) {
  // If version == 0 the library will be ignored by the linker.
  if (version == 0) {
    return version;
  }
  return LAV_CURRENT;
}

/*
    The dynamic linker invokes this function to inform the auditing
    library that it is about to search for a shared object.  The name
    argument is the filename or pathname that is to be searched for.
    cookie identifies the shared object that initiated the search.
    flag is set to one of the following values:
    LA_SER_ORIG
           This is the original name that is being searched for.
          Typically, this name comes from an ELF DT_NEEDED entry, or
          is the filename argument given to dlopen(3).
   LA_SER_LIBPATH
          name was created using a directory specified in
          LD_LIBRARY_PATH.
    LA_SER_RUNPATH
          name was created using a directory specified in an ELF
          DT_RPATH or DT_RUNPATH list.
   LA_SER_CONFIG
          name was found via the ldconfig(8) cache
          (/etc/ld.so.cache).
   LA_SER_DEFAULT
          name was found via a search of one of the default
          directories.
   LA_SER_SECURE
          name is specific to a secure object (unused on Linux).
   As its function result, la_objsearch() returns the pathname that
   the dynamic linker should use for further processing.  If NULL is
   returned, then this pathname is ignored for further processing.
   If this audit library simply intends to monitor search paths,
   then name should be returned.
*/
char *la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag) {
  return const_cast<char *>(name);
}

/*
   The dynamic linker invokes one of these functions when a symbol
   binding occurs between two shared objects that have been marked
   for auditing notification by la_objopen().  The la_symbind32()
   function is employed on 32-bit platforms; the la_symbind64()
   function is employed on 64-bit platforms.
   The sym argument is a pointer to a structure that provides
   information about the symbol being bound.  The structure
   definition is shown in <elf.h>.  Among the fields of this
   structure, st_value indicates the address to which the symbol is
   bound.
   The ndx argument gives the index of the symbol in the symbol
   table of the bound shared object.
   The refcook argument identifies the shared object that is making
   the symbol reference; this is the same identifier that is
   provided to the la_objopen() function that returned
   LA_FLG_BINDFROM.  The defcook argument identifies the shared
   object that defines the referenced symbol; this is the same
   identifier that is provided to the la_objopen() function that
   returned LA_FLG_BINDTO.
   The symname argument points a string containing the name of the
   symbol.
   The flags argument is a bit mask that both provides information
   about the symbol and can be used to modify further auditing of
   this PLT (Procedure Linkage Table) entry.  The dynamic linker may
   supply the following bit values in this argument:
   LA_SYMB_DLSYM
          The binding resulted from a call to dlsym(3).
   LA_SYMB_ALTVALUE
          A previous la_symbind*() call returned an alternate value
          for this symbol.
   By default, if the auditing library implements la_pltenter() and
   la_pltexit() functions (see below), then these functions are
   invoked, after la_symbind(), for PLT entries, each time the
   symbol is referenced.  The following flags can be ORed into
   *flags to change this default behavior:
   LA_SYMB_NOPLTENTER
          Don't call la_pltenter() for this symbol.
   LA_SYMB_NOPLTEXIT
          Don't call la_pltexit() for this symbol.
   The return value of la_symbind32() and la_symbind64() is the
   address to which control should be passed after the function
   returns.  If the auditing library is simply monitoring symbol
   bindings, then it should return sym->st_value.  A different value
   may be returned if the library wishes to direct control to an
   alternate location.
*/
uintptr_t la_symbind32(Elf32_Sym *sym, unsigned int ndx, uintptr_t *refcook,
               uintptr_t *defcook, unsigned int *flags, const char *symname) {
  return sym->st_value;
}

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
               uintptr_t *defcook, unsigned int *flags, const char *symname) {
  return sym->st_value;
}