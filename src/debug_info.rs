//! DWARF debug info parser for sBPF ELF binaries.
//!
//! Extracts source file:line mappings and function names from DWARF sections
//! embedded in Solana .so files compiled with `cargo-build-sbf` in debug mode.

use std::collections::BTreeMap;

use gimli::{EndianSlice, LittleEndian};
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use solana_sbpf::ebpf;

/// Convenience type alias for the gimli reader we use throughout.
type R<'a> = EndianSlice<'a, LittleEndian>;

/// A source code location extracted from DWARF line tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

/// Parsed debug information from an ELF binary.
///
/// Provides PC-to-source and PC-to-function mappings derived from DWARF
/// `.debug_line` and `.debug_info` sections.
pub struct DebugInfo {
    /// Map instruction PC (sBPF instruction index) -> source location.
    line_map: BTreeMap<usize, SourceLocation>,
    /// Map instruction PC (sBPF instruction index) -> demangled function name.
    function_names: BTreeMap<usize, String>,
}

/// Try to demangle a symbol name. If it looks like a Rust mangled symbol,
/// demangle it; otherwise return it as-is.
fn demangle_name(name: &str) -> String {
    // rustc-demangle handles both legacy and v0 Rust mangling schemes.
    // For non-Rust symbols it returns the input unchanged.
    // Use {:#} alternate format to omit the trailing hash suffix.
    format!("{:#}", rustc_demangle::demangle(name))
}

impl DebugInfo {
    /// Parse debug info from raw ELF bytes.
    ///
    /// Returns `None` if the bytes are not a valid ELF or contain no DWARF
    /// debug sections. This is the expected case for release-mode Solana
    /// programs and should not be treated as an error.
    pub fn from_elf_bytes(bytes: &[u8]) -> Option<Self> {
        let object = object::File::parse(bytes).ok()?;

        // Check if any DWARF sections exist before doing heavy work.
        let has_debug = object.section_by_name(".debug_info").is_some()
            || object.section_by_name(".debug_line").is_some();
        if !has_debug {
            return None;
        }
        let text_section_base = Self::text_section_vm_base(&object)?;

        // Load all DWARF section data into owned buffers (no leaks).
        let section_data = Self::load_section_data(&object);
        let dwarf = Self::load_dwarf(&section_data)?;

        let mut line_map = BTreeMap::new();
        let mut function_names = BTreeMap::new();

        // Iterate over compilation units.
        let mut units = dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = match dwarf.unit(header) {
                Ok(u) => u,
                Err(_) => continue,
            };

            // --- Line table: build PC -> source location map ---
            Self::process_line_program(&dwarf, &unit, text_section_base, &mut line_map);

            // --- DIE tree: extract function names from DW_TAG_subprogram ---
            Self::process_die_tree(&dwarf, &unit, text_section_base, &mut function_names);
        }

        if line_map.is_empty() && function_names.is_empty() {
            return None;
        }

        Some(DebugInfo {
            line_map,
            function_names,
        })
    }

    /// Look up source location for an sBPF instruction PC (instruction index).
    ///
    /// If an exact match is not found, returns the location of the nearest
    /// preceding PC that has debug info (since multiple byte offsets may map
    /// to the same source line).
    pub fn source_location(&self, pc: usize) -> Option<&SourceLocation> {
        // Try exact match first, then the nearest preceding entry.
        self.line_map
            .get(&pc)
            .or_else(|| self.line_map.range(..=pc).next_back().map(|(_, v)| v))
    }

    /// Look up the DWARF function name for a PC (returns the enclosing function).
    ///
    /// Uses the nearest preceding function start address, since function entries
    /// record the start PC, not every instruction within.
    pub fn function_name(&self, pc: usize) -> Option<&str> {
        self.function_names
            .range(..=pc)
            .next_back()
            .map(|(_, v)| v.as_str())
    }

    /// Check if any debug info was found.
    pub fn is_empty(&self) -> bool {
        self.line_map.is_empty() && self.function_names.is_empty()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Load all DWARF section data from the ELF, owning any buffers needed
    /// for decompressed sections. Returns a map of section name → data.
    fn load_section_data(object: &object::File<'_>) -> Vec<(String, Vec<u8>)> {
        let mut sections = Vec::new();
        for section in object.sections() {
            if let Ok(name) = section.name() {
                if name.starts_with(".debug") {
                    if let Ok(data) = section.uncompressed_data() {
                        sections.push((name.to_string(), data.into_owned()));
                    }
                }
            }
        }
        sections
    }

    /// Compute the VM address of the first byte of the `.text` section.
    ///
    /// Solana maps bytecode into the program region starting at `MM_BYTECODE_START`.
    /// If the ELF section address is still file-relative, mirror the loader's
    /// normalization by adding the program-region base.
    fn text_section_vm_base(object: &object::File<'_>) -> Option<u64> {
        let text = object.section_by_name(".text")?;
        let addr = text.address();
        Some(if addr >= ebpf::MM_BYTECODE_START {
            addr
        } else {
            addr.saturating_add(ebpf::MM_BYTECODE_START)
        })
    }

    /// Load DWARF data from pre-loaded section data.
    fn load_dwarf(section_data: &[(String, Vec<u8>)]) -> Option<gimli::Dwarf<R<'_>>> {
        let find_section = |name: &str| -> &[u8] {
            section_data
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, data)| data.as_slice())
                .unwrap_or(&[])
        };

        let loader = |section: gimli::SectionId| -> gimli::Result<R<'_>> {
            Ok(EndianSlice::new(find_section(section.name()), LittleEndian))
        };

        let mut dwarf = gimli::Dwarf::load(loader).ok()?;

        let sup_loader = |_section: gimli::SectionId| -> gimli::Result<R<'_>> {
            Ok(EndianSlice::new(&[], LittleEndian))
        };
        dwarf.load_sup(sup_loader).ok()?;

        Some(dwarf)
    }

    /// Process the line number program for a single compilation unit.
    fn process_line_program(
        dwarf: &gimli::Dwarf<R<'_>>,
        unit: &gimli::Unit<R<'_>>,
        text_section_base: u64,
        line_map: &mut BTreeMap<usize, SourceLocation>,
    ) {
        let program = match unit.line_program.clone() {
            Some(p) => p,
            None => return,
        };

        let (program, sequences) = match program.sequences() {
            Ok(s) => s,
            Err(_) => return,
        };
        let header = program.header();

        for sequence in &sequences {
            let mut sm = program.resume_from(sequence);
            while let Ok(Some((_, &row))) = sm.next_row() {
                // Skip end-of-sequence markers.
                if row.end_sequence() {
                    continue;
                }

                let pc = Self::text_address_to_pc(row.address(), text_section_base);

                let line = match row.line() {
                    Some(l) => l.get() as u32,
                    None => continue,
                };

                let column = match row.column() {
                    gimli::ColumnType::LeftEdge => None,
                    gimli::ColumnType::Column(c) => Some(c.get() as u32),
                };

                // Resolve file name.
                let file_entry = match row.file(header) {
                    Some(f) => f,
                    None => continue,
                };

                let file_path = Self::resolve_file_path(dwarf, unit, header, file_entry);
                let file = match file_path {
                    Some(f) => f,
                    None => continue,
                };

                line_map.insert(pc, SourceLocation { file, line, column });
            }
        }
    }

    /// Resolve a file path from a DWARF file entry, combining the directory
    /// and file name attributes.
    fn resolve_file_path(
        dwarf: &gimli::Dwarf<R<'_>>,
        unit: &gimli::Unit<R<'_>>,
        header: &gimli::LineProgramHeader<R<'_>>,
        file_entry: &gimli::FileEntry<R<'_>>,
    ) -> Option<String> {
        let mut path = String::new();

        // Get the directory, if any.
        if let Some(dir) = file_entry.directory(header) {
            let dir_str = dwarf.attr_string(unit, dir).ok()?;
            let dir_s = dir_str.to_string_lossy();
            if !dir_s.is_empty() {
                path.push_str(&dir_s);
                if !dir_s.ends_with('/') {
                    path.push('/');
                }
            }
        }

        // Get the file name.
        let name_str = dwarf.attr_string(unit, file_entry.path_name()).ok()?;
        let name_s = name_str.to_string_lossy();
        path.push_str(&name_s);

        Some(path)
    }

    /// Walk the DIE tree to find DW_TAG_subprogram entries and extract
    /// function names and their start PCs.
    fn process_die_tree(
        dwarf: &gimli::Dwarf<R<'_>>,
        unit: &gimli::Unit<R<'_>>,
        text_section_base: u64,
        function_names: &mut BTreeMap<usize, String>,
    ) {
        let mut entries = unit.entries();
        while let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }

            // Get the start address (low_pc).
            let low_pc = match entry.attr_value(gimli::DW_AT_low_pc) {
                Ok(Some(gimli::AttributeValue::Addr(addr))) => addr,
                _ => continue,
            };

            let pc = Self::text_address_to_pc(low_pc, text_section_base);

            // Prefer linkage_name (mangled) over name, then demangle.
            let name = Self::extract_function_name(dwarf, unit, entry);
            if let Some(name) = name {
                function_names.insert(pc, name);
            }
        }
    }

    /// Convert a DWARF code address into an sBPF instruction index.
    ///
    /// Real ELF DWARF usually records absolute VM addresses; some producers emit
    /// section-relative offsets. Handle both by subtracting the `.text` base when
    /// the address is already in VM space.
    fn text_address_to_pc(address: u64, text_section_base: u64) -> usize {
        let byte_offset = if address >= text_section_base {
            address.saturating_sub(text_section_base)
        } else {
            address
        };
        (byte_offset / ebpf::INSN_SIZE as u64) as usize
    }

    /// Extract a function name from a DW_TAG_subprogram DIE.
    /// Prefers `DW_AT_linkage_name` (which is the mangled name) so we can
    /// demangle it with full namespace info. Falls back to `DW_AT_name`.
    fn extract_function_name(
        dwarf: &gimli::Dwarf<R<'_>>,
        unit: &gimli::Unit<R<'_>>,
        entry: &gimli::DebuggingInformationEntry<R<'_>>,
    ) -> Option<String> {
        // Try DW_AT_linkage_name first (Rust mangled name with full path).
        if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_linkage_name) {
            if let Some(name) = Self::attr_to_string(dwarf, unit, &attr) {
                return Some(demangle_name(&name));
            }
        }

        // Fall back to DW_AT_name (short unmangled name).
        if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_name) {
            if let Some(name) = Self::attr_to_string(dwarf, unit, &attr) {
                return Some(name);
            }
        }

        None
    }

    /// Convert a DWARF attribute value to a String.
    fn attr_to_string(
        dwarf: &gimli::Dwarf<R<'_>>,
        unit: &gimli::Unit<R<'_>>,
        attr: &gimli::Attribute<R<'_>>,
    ) -> Option<String> {
        // Use the generic attr_string path which handles all string forms:
        // DW_FORM_string, DW_FORM_strp, DW_FORM_strx*, DW_FORM_line_strp, etc.
        let s = dwarf.attr_string(unit, attr.value()).ok()?;
        Some(s.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_returns_none() {
        assert!(DebugInfo::from_elf_bytes(&[]).is_none());
    }

    #[test]
    fn invalid_elf_returns_none() {
        let garbage = b"this is not an ELF file at all";
        assert!(DebugInfo::from_elf_bytes(garbage).is_none());
    }

    #[test]
    fn truncated_elf_magic_returns_none() {
        // Valid ELF magic but truncated content.
        let mut data = vec![0x7f, b'E', b'L', b'F'];
        data.extend_from_slice(&[0u8; 12]); // minimal header padding
        assert!(DebugInfo::from_elf_bytes(&data).is_none());
    }

    #[test]
    fn is_empty_on_fresh() {
        let info = DebugInfo {
            line_map: BTreeMap::new(),
            function_names: BTreeMap::new(),
        };
        assert!(info.is_empty());
    }

    #[test]
    fn source_location_lookup() {
        let mut line_map = BTreeMap::new();
        line_map.insert(
            10,
            SourceLocation {
                file: "src/main.rs".into(),
                line: 42,
                column: Some(5),
            },
        );
        line_map.insert(
            20,
            SourceLocation {
                file: "src/main.rs".into(),
                line: 50,
                column: None,
            },
        );

        let info = DebugInfo {
            line_map,
            function_names: BTreeMap::new(),
        };

        // Exact match.
        let loc = info.source_location(10).unwrap();
        assert_eq!(loc.line, 42);
        assert_eq!(loc.file, "src/main.rs");

        // Between two entries: should return the preceding one (PC 10).
        let loc = info.source_location(15).unwrap();
        assert_eq!(loc.line, 42);

        // Before any entry: should return None.
        assert!(info.source_location(5).is_none());
    }

    #[test]
    fn function_name_lookup() {
        let mut function_names = BTreeMap::new();
        function_names.insert(0, "my_crate::process".into());
        function_names.insert(100, "my_crate::validate".into());

        let info = DebugInfo {
            line_map: BTreeMap::new(),
            function_names,
        };

        assert_eq!(info.function_name(0), Some("my_crate::process"));
        assert_eq!(info.function_name(50), Some("my_crate::process"));
        assert_eq!(info.function_name(100), Some("my_crate::validate"));
        assert_eq!(info.function_name(200), Some("my_crate::validate"));
    }

    #[test]
    fn text_address_to_pc_normalizes_vm_addresses() {
        let text_base = ebpf::MM_BYTECODE_START + 24;
        assert_eq!(DebugInfo::text_address_to_pc(text_base, text_base), 0);
        assert_eq!(DebugInfo::text_address_to_pc(text_base + 16, text_base), 2);
    }

    #[test]
    fn text_address_to_pc_accepts_relative_offsets() {
        let text_base = ebpf::MM_BYTECODE_START + 24;
        assert_eq!(DebugInfo::text_address_to_pc(16, text_base), 2);
    }

    #[test]
    fn demangle_rust_symbol() {
        let mangled = "_ZN4test3foo17h1234567890abcdefE";
        let result = demangle_name(mangled);
        assert!(result.contains("test"));
        assert!(result.contains("foo"));
        // Should not contain the hash suffix in demangled form.
        assert!(!result.contains("h1234567890abcdef"));
    }

    #[test]
    fn demangle_plain_name() {
        let plain = "some_c_function";
        assert_eq!(demangle_name(plain), "some_c_function");
    }
}
