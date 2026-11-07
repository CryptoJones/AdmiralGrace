//! Type libraries: the types and function signatures a shared library or
//! DLL ships, applied when an image imports it (#376).
//!
//! A type library is C in the same dialect [`crate::ctype`] reads —
//! `typedef`s, `struct`s, `union`s, `enum`s, and one prototype a function
//! — grouped under the library's name, with two index forms beside the
//! plain name:
//!
//! - **ordinals**: a DLL exports by position, and an image imports such a
//!   function by number, `#[ordinal(12)] int f(int x);`. [`TypeLibrary`]'s
//!   `by_ordinal` maps the number to the signature.
//! - **syscalls**: a syscall is a function taking arguments by number.
//!   `#[syscall(2)] int open(const char *path, int flags);` gives number 2
//!   that prototype; a syscall instruction whose number matches takes its
//!   types. The built-in Linux table ([`linux_syscalls`]) covers the
//!   common x86-64 numbers.
//!
//! The built-in [`TypeLibSet::builtin`] is the library [`crate::propagate`]
//! reads, split by library: libc (the C library and POSIX), kernel32 and
//! user32 (Windows), and the Linux syscall table. Every
//! library answers by name — `strlen`, `ReadFile`, `open` — exactly as the
//! old table did; an import also names its library (`ntdll.dll`, libc), and
//! [`TypeLibSet::for_import`] chooses the library by that name first, then
//! by ordinal, then by the plain builtin table.
//!
//! Analyst and project types win over a library's where both define a
//! name. A library's signatures apply at an import's slot; the names that
//! resolve become a [`TypeLibSet::by_name`] the propagation and the lift
//! read.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::ctype::TypeText;
use crate::propagate::{read_library_as, Prototype};
use crate::types::DataModel;

/// The C of the built-in libc library: the C library and POSIX prototypes
/// the engine has always carried.
pub const LIBC: &str = include_str!("typelib/libc.h");
/// The C of the built-in kernel32 library.
pub const KERNEL32: &str = include_str!("typelib/kernel32.h");
/// The C of the built-in user32 library.
pub const USER32: &str = include_str!("typelib/user32.h");
/// The C of the built-in ole32 library: COM's run-time.
pub const OLE32: &str = include_str!("typelib/ole32.h");

/// One shared library's type library: its name, its definitions and its
/// signatures by name, by ordinal and by syscall number.
#[derive(Debug, Clone)]
pub struct TypeLibrary {
    /// The library's name — `libc`, `kernel32.dll`, `libm.so` — as the
    /// image names it, lower-cased where the image does.
    pub name: String,
    /// The definitions of the types the signatures name, one declaration
    /// each, in order.
    pub definitions: Vec<TypeText>,
    /// The signatures by plain name, a stub's decoration stripped on
    /// lookup (`__imp_ReadFile`, `_open`, `j_read`).
    by_name: BTreeMap<String, Prototype>,
    /// The signatures by ordinal, for imports by number.
    by_ordinal: BTreeMap<u64, Prototype>,
    /// The signatures by syscall number.
    by_syscall: BTreeMap<u64, Prototype>,
}

impl TypeLibrary {
    /// Read `source` as the library `name` under `model`: the type
    /// declarations are built, the prototypes are read with their types,
    /// and an `#[ordinal(N)]` or `#[syscall(N)]` line names its number.
    /// `base`, when given, is a library whose type definitions the store
    /// carries first — kernel32 names `HANDLE` and `DWORD`, and the
    /// syscalls name `off_t` and `struct sockaddr`, all of which libc
    /// defines; see [`read_library_as`].
    pub fn parse(name: &str, source: &str, base: Option<&str>, model: DataModel) -> TypeLibrary {
        let (definitions, mut prototypes, by_ordinal, by_syscall) =
            read_library_as(source, base, model);
        let mut by_name = BTreeMap::new();
        for prototype in prototypes.drain(..) {
            by_name.entry(prototype.name.clone()).or_insert(prototype);
        }
        TypeLibrary {
            name: name.to_string(),
            definitions,
            by_name,
            by_ordinal,
            by_syscall,
        }
    }

    /// The library's name without its path or extension: `kernel32.dll` is
    /// `kernel32`, `libc.so.6` is `libc`.
    fn stem(&self) -> String {
        stem_of(&self.name)
    }

    /// Look up `name` under an import's or a stub's decoration, exactly as
    /// the built-in table does.
    fn by_name(&self, name: &str) -> Option<&Prototype> {
        let full = name.trim();
        let bare = full.split('@').next().unwrap_or(full);
        if let Some(found) = self.by_name.get(bare) {
            return Some(found);
        }
        for prefix in ["__imp__", "__imp_", "_imp_", "j_", "_"] {
            if let Some(rest) = bare.strip_prefix(prefix) {
                if let Some(found) = self.by_name.get(rest) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Look up an ordinal.
    pub fn by_ordinal(&self, ordinal: u64) -> Option<&Prototype> {
        self.by_ordinal.get(&ordinal)
    }

    /// Look up a syscall number.
    pub fn by_syscall(&self, number: u64) -> Option<&Prototype> {
        self.by_syscall.get(&number)
    }

    /// Every signature by name, in order.
    pub fn prototypes(&self) -> impl Iterator<Item = &Prototype> {
        self.by_name.values()
    }
}

/// What a library is named in an image, without its path or extension.
fn stem_of(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base.to_lowercase();
    let base = base.strip_suffix(".dll").unwrap_or(&base);
    let base = base.strip_suffix(".so").unwrap_or(base);
    let base = base.strip_suffix(".dylib").unwrap_or(base);
    // `libc.so.6`: the version tail follows the first dot after a stem
    // that is not itself dotted, so cut at the first dot.
    if let Some(at) = base.find('.') {
        base[..at].to_string()
    } else {
        base.to_string()
    }
}

/// A set of type libraries the engine ships and reads, under one data
/// model: the built-ins, the ones a project adds, and the syscalls.
#[derive(Debug, Clone)]
pub struct TypeLibSet {
    /// The libraries, in the order they are consulted: the first match
    /// wins.
    pub libraries: Vec<TypeLibrary>,
}

/// The built-in sets read so far, one a data model.
type BuiltinCache = OnceLock<Mutex<Vec<(DataModel, Arc<TypeLibSet>)>>>;

impl TypeLibSet {
    /// The built-in libraries under `model`, read once.
    pub fn builtin(model: DataModel) -> Arc<TypeLibSet> {
        static CACHE: BuiltinCache = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
        let mut held = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, found)) = held.iter().find(|(m, _)| *m == model) {
            return Arc::clone(found);
        }
        let mut libraries = vec![
            TypeLibrary::parse("libc", LIBC, None, model),
            TypeLibrary::parse("kernel32", KERNEL32, Some(LIBC), model),
            TypeLibrary::parse("user32", USER32, Some(LIBC), model),
            TypeLibrary::parse("ole32", OLE32, Some(LIBC), model),
        ];
        libraries.push(linux_syscalls(model));
        let set = Arc::new(TypeLibSet { libraries });
        held.push((model, Arc::clone(&set)));
        set
    }

    /// The library named `name`, by its stem: `kernel32.dll`, `KERNEL32`,
    /// `libc.so.6` all name themselves.
    pub fn library(&self, name: &str) -> Option<&TypeLibrary> {
        let stem = stem_of(name);
        self.libraries.iter().find(|lib| lib.stem() == stem)
    }

    /// The signature an import names: the import's library by name, then by
    /// ordinal in that library, then by plain name across every library,
    /// then by ordinal across every library — an image imports `strlen`
    /// whose library is only in its DT_NEEDED, and the table must still
    /// answer. Ordinal spaces are per-DLL, so a caller that knows the
    /// import's library should resolve the number within that library (see
    /// [`TypeLibSet::library`] and [`TypeLibrary::by_ordinal`]) rather than
    /// rely on the last, library-blind step.
    pub fn for_import(
        &self,
        library_name: Option<&str>,
        name: Option<&str>,
        ordinal: Option<u64>,
    ) -> Option<&Prototype> {
        if let Some(library_name) = library_name {
            if let Some(lib) = self.library(library_name) {
                if let Some(name) = name {
                    if let Some(found) = lib.by_name(name) {
                        return Some(found);
                    }
                }
                if let Some(ordinal) = ordinal {
                    if let Some(found) = lib.by_ordinal(ordinal) {
                        return Some(found);
                    }
                }
            }
        }
        if let Some(name) = name {
            for lib in &self.libraries {
                if let Some(found) = lib.by_name(name) {
                    return Some(found);
                }
            }
        }
        if let Some(ordinal) = ordinal {
            for lib in &self.libraries {
                if let Some(found) = lib.by_ordinal(ordinal) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// The signature for a syscall number, from every library's syscall
    /// table — the built-in Linux table above all.
    pub fn for_syscall(&self, number: u64) -> Option<&Prototype> {
        self.libraries
            .iter()
            .filter_map(|lib| lib.by_syscall(number))
            .next()
    }

    /// Every signature by plain name, in library order.
    pub fn prototypes(&self) -> impl Iterator<Item = &Prototype> {
        self.libraries.iter().flat_map(|lib| lib.prototypes())
    }

    /// The definitions of every library, in order: what a program written
    /// from the inferred types declares ahead of its functions.
    pub fn definitions(&self) -> Vec<TypeText> {
        self.libraries
            .iter()
            .flat_map(|lib| lib.definitions.clone())
            .collect()
    }
}

/// The Linux syscall signatures the engine knows: the x86-64 numbers a
/// `syscall` instruction carries, with their argument types.
pub fn linux_syscalls(model: DataModel) -> TypeLibrary {
    /// The numbers the table knows, with their prototypes.
    const SYSCALLS: &str = r"
#[syscall(0)] ssize_t read(int fd, void *buf, size_t count);
#[syscall(1)] ssize_t write(int fd, const void *buf, size_t count);
#[syscall(2)] int open(const char *path, int flags, ...);
#[syscall(3)] int close(int fd);
#[syscall(5)] int fstat(int fd, void *buf);
#[syscall(8)] off_t lseek(int fd, off_t offset, int whence);
#[syscall(9)] void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
#[syscall(10)] int mprotect(void *addr, size_t length, int prot);
#[syscall(11)] int munmap(void *addr, size_t length);
#[syscall(12)] int brk(void *addr);
#[syscall(21)] int access(const char *path, int mode);
#[syscall(32)] int dup(int fd);
#[syscall(33)] int dup2(int old, int new);
#[syscall(39)] pid_t getpid(void);
#[syscall(42)] int connect(int fd, const struct sockaddr *addr, socklen_t len);
#[syscall(43)] int accept(int fd, struct sockaddr *addr, socklen_t *len);
#[syscall(44)] ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen);
#[syscall(45)] ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *len);
#[syscall(56)] int clone(int flags, void *stack, int *parent, unsigned long *tls, int *child);
#[syscall(57)] int fork(void);
#[syscall(59)] int execve(const char *path, char **argv, char **envp);
#[syscall(60)] int exit(int status);
#[syscall(61)] int wait4(pid_t pid, int *status, int options, void *rusage);
#[syscall(72)] int fcntl(int fd, int cmd, unsigned long arg);
#[syscall(96)] int gettimeofday(struct timeval *tv, void *tz);
#[syscall(101)] int ptrace(int request, pid_t pid, void *addr, void *data);
#[syscall(102)] unsigned int getuid(void);
#[syscall(104)] int setuid(unsigned int uid);
#[syscall(107)] int geteuid(void);
#[syscall(227)] int mremap(void *old, size_t old_len, size_t new_len, int flags, void *new_addr);
#[syscall(231)] void exit_group(int status);
";
    TypeLibrary::parse("linux-syscalls", SYSCALLS, Some(LIBC), model)
}

/// What an image imports: a slot, the library it comes from when the
/// container names one, the name, and the ordinal when it imports by
/// number. PE imports carry all three; an ELF's carry only the name.
#[derive(Debug, Clone, PartialEq)]
pub struct Import {
    /// The slot — the GOT or IAT entry the loader fills.
    pub slot: u64,
    /// The library it imports from: `kernel32.dll`, `libc`.
    pub library: Option<String>,
    /// The name it imports by, when by name.
    pub name: Option<String>,
    /// The ordinal it imports by, when by number.
    pub ordinal: Option<u64>,
}

impl Import {
    /// The signature in `set` this import takes, if the libraries know it.
    pub fn prototype<'a>(&self, set: &'a TypeLibSet) -> Option<&'a Prototype> {
        set.for_import(self.library.as_deref(), self.name.as_deref(), self.ordinal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DataModel;

    #[test]
    fn a_library_is_read_by_name_ordinal_and_syscall() {
        let source = r"
typedef int my_t;
struct pair { my_t a; my_t b; };
#[ordinal(12)] int by_number(my_t x);
#[syscall(99)] int by_number_syscall(int x);
int by_name(my_t x);
";
        let library = TypeLibrary::parse("testdll", source, None, DataModel::LP64);
        assert_eq!(library.definitions.len(), 2);
        assert!(library.by_name("by_name").is_some());
        assert!(library.by_name("__imp_by_name").is_some());
        assert!(library.by_ordinal(12).is_some());
        assert!(library.by_ordinal(13).is_none());
        assert!(library.by_syscall(99).is_some());
        assert!(library.by_syscall(2).is_none());
        // An ordinal routes the prototype to its number and keeps its name:
        // a DLL export has both, so `by_number` answers by name too.
        assert!(library.by_name("by_number").is_some());
        // A syscall is named by its number alone, not by its C name.
        assert!(library.by_name("by_number_syscall").is_none());
    }

    #[test]
    fn the_library_name_is_the_stem_of_its_file() {
        assert_eq!(stem_of("kernel32.dll"), "kernel32");
        assert_eq!(stem_of("KERNEL32.DLL"), "kernel32");
        assert_eq!(stem_of("libc.so.6"), "libc");
        assert_eq!(stem_of("/usr/lib/libm.so"), "libm");
        assert_eq!(stem_of("libSystem.B.dylib"), "libsystem");
    }

    #[test]
    fn an_import_finds_its_signature_by_library_then_name_then_ordinal() {
        let set = TypeLibSet {
            libraries: vec![
                TypeLibrary::parse("kernel32", KERNEL32, Some(LIBC), DataModel::LLP64),
                TypeLibrary::parse("libc", LIBC, None, DataModel::LLP64),
            ],
        };
        // By library and name.
        let import = Import {
            slot: 0x1000,
            library: Some("kernel32.dll".to_string()),
            name: Some("ReadFile".to_string()),
            ordinal: None,
        };
        assert_eq!(
            import.prototype(&set).map(|p| p.name.as_str()),
            Some("ReadFile")
        );
        // An unknown library falls through to the plain name.
        let unknown_library = Import {
            slot: 0,
            library: Some("ws2_32.dll".to_string()),
            name: Some("strlen".to_string()),
            ordinal: None,
        };
        assert_eq!(
            unknown_library.prototype(&set).map(|p| p.name.as_str()),
            Some("strlen")
        );
        // An import by ordinal resolves in its library.
        let source = r"
#[ordinal(42)] int FortyTwo(void);
";
        let set = TypeLibSet {
            libraries: vec![TypeLibrary::parse("dll", source, None, DataModel::LLP64)],
        };
        let by_ordinal = Import {
            slot: 0,
            library: Some("dll.dll".to_string()),
            name: None,
            ordinal: Some(42),
        };
        assert_eq!(
            by_ordinal.prototype(&set).map(|p| p.name.as_str()),
            Some("FortyTwo")
        );
        assert!(by_ordinal.prototype(&set).is_some());
        let unknown_ordinal = Import {
            slot: 0,
            library: Some("dll.dll".to_string()),
            name: None,
            ordinal: Some(43),
        };
        assert!(unknown_ordinal.prototype(&set).is_none());
    }

    #[test]
    fn the_builtin_libraries_answer_by_name_and_number() {
        let set = TypeLibSet::builtin(DataModel::LP64);
        assert!(set.libraries.iter().any(|lib| lib.name == "libc"));
        assert!(set.libraries.iter().any(|lib| lib.name == "kernel32"));
        // A known prototype by plain name.
        let import = Import {
            slot: 0,
            library: None,
            name: Some("strlen".to_string()),
            ordinal: None,
        };
        assert!(import.prototype(&set).is_some());
        // A known prototype under a decoration.
        let import = Import {
            slot: 0,
            library: None,
            name: Some("__imp_ReadFile".to_string()),
            ordinal: None,
        };
        assert!(import.prototype(&set).is_some());
        // The library name picks the library whose name matches.
        assert!(set.library("kernel32.dll").is_some());
        assert!(set.library("libc.so.6").is_some());
        assert!(set.library("ws2_32.dll").is_none());
        // The syscall table.
        let syscall = set.for_syscall(2).map(|p| p.name.as_str());
        assert_eq!(syscall, Some("open"));
        assert!(set.for_syscall(999_999).is_none());
    }
}
