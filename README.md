# ManualMap-Injector 💉

A high-performance C++ DLL injector based on the **Manual Mapping** technique. Injects DLLs into target processes without using standard Windows APIs like `LoadLibrary`, and automatically cleans all execution traces afterwards.

![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Windows](https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows&logoColor=white)
![Build](https://img.shields.io/github/actions/workflow/status/nullptrflow/ManualMap-Injector/build.yml?style=for-the-badge)

> [!CAUTION]
> **Disclaimer:** This project is for educational purposes only. Use this software at your own risk. I am not responsible for any damage or misuse of this tool.

---

### Features 🚀

- **PE Header Parsing:** Manually parses DOS and NT headers to map sections correctly.
- **Base Relocation:** Corrects absolute memory addresses if the DLL is loaded at a different base address.
- **IAT Resolution:** Manually resolves the Import Address Table using `GetProcAddress` and `LoadLibraryA`.
- **TLS Support:** Executes Thread Local Storage (TLS) callbacks before calling the DLL entry point.
- **Stealth Injection:** Does not leave traces in the `InLoadOrderModuleList` (PEB).
- **Trace Cleanup:** Automatically removes execution traces from Registry (RecentDocs, UserAssist, BAM, ShellBags) and filesystem (Prefetch, Recent).
- **Colored Logger:** Real-time feedback with timestamped log levels (Info, Warning, Error, Input).
- **SE_DEBUG Privileges:** Automatically acquires debug privileges for maximum process access.
- **Process Search:** Find target process by name instead of manually looking up PID.

### Technical Details 🛠️

- **Shellcode Execution:** Injects a custom shellcode stub into the target process to handle final mapping steps and execute `DllMain`.
- **Memory Management:** Uses `VirtualAllocEx` and `WriteProcessMemory` for remote memory manipulation.
- **Registry Cleaner:** Deep cleans Windows artifacts across RecentDocs, ShellBags, UserAssist and BAM registry keys.
- **Filesystem Cleaner:** Removes `.pf` Prefetch files and Recent folder entries linked to the injector.
- **x64 Only:** Targets 64-bit processes.

### Quick Start ⚡

1. **Build:**
   - Open in **Visual Studio 2022**, select **Release x64**, build.
   - Or grab the latest `.exe` from [Releases](https://github.com/nullptrflow/ManualMap-Injector/releases).

2. **Usage:**
   ```bash
   # By PID
   ManualMapInjector.exe <PID> <PathToDll>

   # By process name (will prompt)
   ManualMapInjector.exe <PathToDll>
   ```

### Project Structure 📦

```
src/
├── EntryPoint.cpp          — Entry point, argument parsing, injection flow
├── ManualMap.cpp/.h        — Core manual mapping + shellcode
├── sdk/
│   ├── Logger.h            — Colored timestamped logger
│   ├── ntdefines.h         — NT function typedefs
│   └── ntstruct.h          — PEB, LDR, NT structures
├── utils/
│   ├── Process.h/.cpp      — Process search, name utils, privilege adjustment
│   └── memory.hpp          — Remote memory read/write, module base, pattern scan
└── cleaners/
    ├── Registry.h/.cpp     — Registry trace removal
    └── Explorer.h/.cpp     — Prefetch and Recent file removal
```

---

Created by [nullptrflow](https://github.com/nullptrflow)
