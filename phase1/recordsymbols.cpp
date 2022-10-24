#include <elf.h>
#include <link.h>

#include <filesystem>
#include <iostream>
#include <sstream>
#include <unordered_map>

#include "sqlite3.h"

// A pointer to the database that exists
static sqlite3 *db;

static std::unordered_map<uintptr_t, std::string> cookie_map;

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
  std::cout << "Taking control of the linking search...." << std::endl;

  /**
   * Let's setup our sqlite3 database now.
   */
  int error = sqlite3_open("database.db", &db);
  if (error != SQLITE_OK) {
    std::cerr << sqlite3_errstr(error) << std::endl;
    exit(1);
  }

  // Create our table
  std::string sql =
      R""""(
      DROP TABLE IF EXISTS Libraries;
      DROP TABLE IF EXISTS Symbols;
      DROP TABLE IF EXISTS Usages;
      CREATE TABLE Libraries(Name TEXT PRIMARY KEY, Path TEXT);
      CREATE TABLE Symbols(Name TEXT, Library TEXT);
      CREATE TABLE Usages(Library TEXT, Symbol Text);
      )"""";
  char *err_msg = nullptr;
  error = sqlite3_exec(db, sql.c_str(), 0, 0, &err_msg);

  if (error != SQLITE_OK) {
    std::cerr << err_msg << std::endl;
    sqlite3_free(err_msg);
    sqlite3_close(db);
    exit(1);
  }

  return LAV_CURRENT;
}

/**
 * Could not get my interpretation of the code below to work.
 * This is the code from Musl's dynamic linker
 * @see
 * http://git.musl-libc.org/cgit/musl/tree/src/ldso/dynlink.c?id=c5ab5bd3be15eb9d49222df132a51ae8e8f78cbc#n1554
 */
size_t gnu_hash_symtab_len_musl(const ElfW(Word) * base_address) {
  uint32_t nsym;
  const uint32_t *buckets;
  const uint32_t *hashval;
  buckets = reinterpret_cast<const uint32_t *>(
      base_address + 4 + (base_address[2] * sizeof(size_t) / 4));
  for (size_t i = nsym = 0; i < base_address[0]; i++) {
    if (buckets[i] > nsym) nsym = buckets[i];
  }
  if (nsym) {
    nsym -= base_address[1];
    hashval = buckets + base_address[0] + nsym;
    do nsym++;
    while (!(*hashval++ & 1));
  }
  return nsym;
}

size_t gnu_hash_symtab_len(const ElfW(Word) * base_address) {
  // https://chromium-review.googlesource.com/c/crashpad/crashpad/+/876879
  // See https://flapenguin.me/2017/05/10/elf-lookup-dt-gnu-hash/ and
  // https://sourceware.org/ml/binutils/2006-10/msg00377.html
  // http://git.musl-libc.org/cgit/musl/tree/src/ldso/dynlink.c?id=c5ab5bd3be15eb9d49222df132a51ae8e8f78cbc#n1554
  struct gnu_hash_header {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
    // uint64_t bloom[bloom_size]; /* uint32_t for 32-bit binaries */
    // uint32_t buckets[nbuckets];
    // uint32_t chain[];
  };

  const gnu_hash_header *header =
      reinterpret_cast<const gnu_hash_header *>(base_address);

  const uint32_t *buckets = reinterpret_cast<const unsigned *>(
      base_address + sizeof(gnu_hash_header) +
      (header->bloom_size * (sizeof(size_t) / 4)));

  // Locate the chain that handles the largest index bucket.
  uint32_t last_symbol = 0;
  for (uint32_t i = 0; i < header->nbuckets; ++i) {
    last_symbol = std::max(buckets[i], last_symbol);
  }

  // Walk the bucket's chain to add the chain length to the total.
  const uint32_t *chain = buckets + header->nbuckets;
  for (;;) {
    const uint32_t *chain_entry =
        chain + (last_symbol - header->symoffset) * sizeof(chain_entry);
    ++last_symbol;
    // If the low bit is set, this entry is the end of the chain.
    if (*chain_entry & 1) break;
  }

  return last_symbol;
}

/*
    The dynamic linker calls this function when a new shared object
    is loaded.  The map argument is a pointer to a link-map structure
    that describes the object.  The lmid field has one of the
    following values
    LM_ID_BASE
          Link map is part of the initial namespace.
    LM_ID_NEWLM
          Link map is part of a new namespace requested via
          dlmopen(3).
    cookie is a pointer to an identifier for this object.  The
    identifier is provided to later calls to functions in the
    auditing library in order to identify this object.  This
    identifier is initialized to point to object's link map, but the
    audit library can change the identifier to some other value that
    it may prefer to use to identify the object.
    As its return value, la_objopen() returns a bit mask created by
    ORing zero or more of the following constants, which allow the
    auditing library to select the objects to be monitored by
    la_symbind*():
    LA_FLG_BINDTO
          Audit symbol bindings to this object.
    LA_FLG_BINDFROM
          Audit symbol bindings from this object.
    A return value of 0 from la_objopen() indicates that no symbol
    bindings should be audited for this object.
*/
unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
  // This nis not a real shared library and is placed by the Kernel
  // The rest of the code won't work for it so just skip it for now.
  // https://man7.org/linux/man-pages/man7/vdso.7.html
  // TODO(fmzakari): Kernel docs say it's a real ELF format so it should work?
  if (std::string(map->l_name) == "linux-vdso.so.1") {
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
  }

  std::ostringstream s;
  s << "INSERT INTO Libraries(Name, Path) VALUES ('" << map->l_name << "','"
    << std::filesystem::path(map->l_name).filename().string() << "'"
    << ");";
  std::string sql = s.str();

  char *err_msg = nullptr;
  int error = sqlite3_exec(db, sql.c_str(), 0, 0, &err_msg);

  if (error != SQLITE_OK) {
    std::cerr << err_msg << std::endl;
    sqlite3_free(err_msg);
    sqlite3_close(db);
    exit(1);
  }

  // store reference of the cookie as we will need it later
  cookie_map.insert({*cookie, std::string(map->l_name)});

  // Keep reference to sections we care about
  const char *strtab = nullptr;
  const ElfW(Sym) *elf_sym = nullptr;
  size_t sym_cnt = 0;
  const ElfW(Dyn) *const dyn_start = map->l_ld;
  for (const ElfW(Dyn) *dyn = dyn_start; dyn->d_tag != DT_NULL; ++dyn) {
    ElfW(Addr) base_address = dyn->d_un.d_ptr;

    switch (dyn->d_tag) {
      case (DT_STRTAB): {
        strtab = reinterpret_cast<const char *>(base_address);
        break;
      }
      case (DT_SYMTAB): {
        elf_sym = reinterpret_cast<const ElfW(Sym) *>(base_address);
        break;
      }
      case (DT_GNU_HASH): {
        sym_cnt = gnu_hash_symtab_len_musl(
            reinterpret_cast<const ElfW(Word) *>(base_address));
        break;
      }
      case (DT_HASH): {
        // https://flapenguin.me/elf-dt-hash
        struct hash_header {
          uint32_t nbucket;
          uint32_t nchain;
        };
        const hash_header *header =
            reinterpret_cast<const hash_header *>(base_address);
        sym_cnt = header->nbucket;
        break;
      }
    }
  }

  s.str(std::string());  // clear the string stream
  s << "INSERT INTO Symbols(Name, Library) VALUES ";

  for (size_t sym_index = 0; sym_index < sym_cnt; ++sym_index) {
    const char *sym_name = &strtab[elf_sym[sym_index].st_name];
    s << "('" << sym_name << "','" << map->l_name << "'"
      << ")";
    if (sym_index < sym_cnt - 1) {
      s << ",";
    }
  }

  s << ";";
  sql = s.str();
  error = sqlite3_exec(db, sql.c_str(), 0, 0, &err_msg);
  if (error != SQLITE_OK) {
    std::cerr << err_msg << std::endl;
    sqlite3_free(err_msg);
    sqlite3_close(db);
    exit(1);
  }

  return LA_FLG_BINDTO | LA_FLG_BINDFROM;
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
                       uintptr_t *defcook, unsigned int *flags,
                       const char *symname) {
  auto ref_library_it = cookie_map.find(*refcook);
  if (ref_library_it == cookie_map.end()) {
    std::cerr << "Could not find a cookie. Assertion failed." << std::endl;
    exit(1);
  }
  auto ref_library = ref_library_it->second;

  return sym->st_value;
}

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
                       uintptr_t *defcook, unsigned int *flags,
                       const char *symname) {
  return sym->st_value;
}