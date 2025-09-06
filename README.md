# Carbide

Carbide is a **tiny, cross-platform, self-hosting build/recipe runner** written in C.  
It compiles your `Carbidefile.c` into a shared library on the fly, **caches the result**, and dispatches commands you register.  
No Node, no Python, no heavy frameworks, **just a C compiler**.

---

## Features

- **Cross-platform**: Linux, Windows (currently untested), macOS
- **Self-hosting**: this repo builds Carbide using Carbide
- **Fast builds**: automatic fingerprinting and caching
- **Batteries included**:
  - Colored logs
  - Path & filesystem helpers
  - Recursive globbing
  - Rebuild checks
  - Portable process execution
- **Zero daemons, zero magic**

---

> **Note:**  
> `Carbidefile.c` in this repository **reimplements** the build logic of `make.sh` directly in Carbide to bootstrap the driver.  
> In your own project, your `Carbidefile.c` defines custom commands for your build.

---

## Concepts

- **Driver (`carbide`)**  
  The executable that orchestrates everything:
  1. Detects a C compiler
  2. (Re)compiles `Carbidefile.c` into `.carbide/Carbidefile.{so|dylib|dll}` if needed
  3. Loads the compiled recipe dynamically
  4. Dispatches the selected command

- **Recipe (`Carbidefile.c`)**  
  Your project's build script written in C. You register commands using the Carbide API.

- **Cache & fingerprinting**  
  Carbide automatically detects when a rebuild is needed based on:
  - API version
  - Compiler kind & path
  - OS + architecture
  - `Carbidefile.c` contents  
  Cache metadata is stored in `.carbide/Carbidefile.stamp`.

---

## Getting started

1. **Add a `Carbidefile.c`** to your repository (your recipe).
2. **Build the driver** (or grab a binary):
   ```bash
   # On Linux/macOS
   ./make.sh

   # On Windows
   make.bat
   ```
3. **Run Carbide**:
    ```bash
    carbide <optional command name>
    ```
4. **Carbide compiles and caches your recipe, then dispatches the command.**

---

## CLI Overview 

```bash
carbide [--verbose] <command> [...args]
```

- Built-in commands:
    - `help`: lists available commands. (can be overriden by providing a command called `help` [example](Carbidefile.c#456))

## FAQ

### Why is there a `Carbidefile.c` in this repo?
- Carbide **bootstraps** itself using its own mechanism.  
The included `Carbidefile.c` is for building Carbide, and can be used as a learning resource.
### Should my recipe define `CB_API_IMPL`?
- **No.**
### Where does Carbide write artifacts?
- Everything goes under `.carbide/`:
    - Compiled recipe: `.carbide/Carbidefile.{so|dylib|dll}`
    - Cache stamp: `.carbide/Carbidefile.stamp`
    - Default output dir: `.carbide/out` (via `cb_out_root()`).

## Roadmap

- JSON output mode for tooling integration (`compile_commands.json` generation built-in)
- Test functionality on windows.

## License

Carbide is licensed under the [MIT License](LICENSE).
