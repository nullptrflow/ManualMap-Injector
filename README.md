# ManualMap-Injector 💉

A high-performance C++ DLL injector based on the **Manual Mapping** technique. Designed for educational purposes to demonstrate how to load modules into a target process without using standard Windows APIs like `LoadLibrary`.

![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white) 
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Windows](https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows&logoColor=white)

> [!CAUTION]
> **Disclaimer:** This project is for educational purposes only. Manual mapping is a technique often used in security research and malware analysis. Use this software at your own risk. I am not responsible for any damage or misuse of this tool.

---

### Features 🚀

- **PE Header Parsing:** Manually parses DOS and NT headers to map sections correctly.
- **Base Relocation:** Corrects absolute memory addresses if the DLL is loaded at a different base address.
- **IAT Resolution:** Manually resolves the Import Address Table using `GetProcAddress` and `LoadLibraryA`.
- **TLS Support:** Executes Thread Local Storage (TLS) callbacks before calling the DLL entry point.
- **Stealth Injection:** Does not leave traces in the `InLoadOrderModuleList` (PEB), making it harder to detect via standard module enumeration.

### Technical Details 🛠️

- **Shellcode Execution:** Injects a custom shellcode stub into the target process to handle final mapping steps and execute `DllMain`.
- **Memory Management:** Uses `VirtualAllocEx` and `WriteProcessMemory` for remote memory manipulation.
- **Multi-Architecture:** Supports both `x86` and `x64` targets (ensure the injector and target match).

### Quick Start ⚡

1. **Build the Project:**
   - Open the solution in **Visual Studio 2022**.
   - Select **Release** configuration and your target architecture (`x64` recommended).
   - Build the solution.

2. **Usage:**
   - Run the compiled executable via command line:
     ```bash
     ManualMapInjector.exe <ProcessID> <PathToDll>
     ```

### Project Structure 📦

- `src/main.cpp` - Entry point and user interface logic.
- `src/ManualMap.cpp` - Core mapping logic and shellcode implementation.
- `src/ManualMap.h` - Structure definitions and function prototypes.

---

Created by [nullptrflow](https://github.com/nullptrflow)
