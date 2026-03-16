# amfree

ObjC runtime method swizzle inside `amfid` to bypass AMFI code signature validation for ad-hoc signed binaries in allowlisted directories.

> **Requires**: macOS arm64 with SIP disabled (`csrutil disable`), root access.

## Install

```bash
brew install retX0/tap/amfree
```

## Usage

```bash
sudo amfree --path /path/to/your/project/

# multiple directories
sudo amfree --path /path/one/ --path /path/two/

# verbose output
sudo amfree -v --path /path/to/project/
```

## Build from Source

```bash
make
sudo bin/amfree --path /path/to/your/project/
bin/test_ent    # should run (has private entitlements)
```

## Background: How macOS Code Signing Works

macOS enforces code signatures at two layers:

1. **Kernel (AMFI.kext)** — synchronous check during `execve`. Validates certificate chains and hard-blocks restricted entitlements that require Apple signing. This layer is not bypassable from userspace.

2. **Userspace (amfid daemon)** — receives validation requests from the kernel via MIG IPC. Calls `-[AMFIPathValidator_macos validateWithError:]` to perform full validation: parses the code signature, computes the **cdhash**, checks entitlements, and sends results (including the cdhash) back to the kernel.

The kernel **trusts amfid's reply** — if amfid says a binary is valid and provides a cdhash, the kernel accepts it. This is the attack surface.

## Design: Why This Approach

### Why not inline code patching?

Overwriting instructions in amfid's `__TEXT` segment (the classic hook approach) is impossible on modern macOS. `amfid` is a **platform binary** — the kernel verifies the hash of every code page at execution time. Modifying even one byte triggers `SIGKILL (Code Signature Invalid)`.

### Why not LLDB breakpoints?

Tools like [amfidont](https://github.com/zqxwce/amfidont) use debugserver breakpoints to intercept `validateWithError:` and patch registers at return. This works, but:

- Breakpoint-based interception adds overhead to every validation call
- Requires careful register-state management across debugserver protocol
- The hook logic lives in the injector process, not in amfid — more IPC, more latency

### Why ObjC method swizzle?

`class_replaceMethod` modifies the **ObjC runtime metadata** (in the writable `__DATA` segment), not the code pages. The kernel's code-page integrity checks don't apply. Once installed, the hook runs natively inside amfid with zero IPC overhead — just a normal method dispatch.

### Why call-through (not direct override)?

The original `validateWithError:` does far more than return YES/NO. Internally it parses the Mach-O code signature, computes the **cdhash**, and populates internal state that gets serialized into the MIG reply to the kernel. If we skip the original method and just return YES, the kernel receives a reply with no valid cdhash and kills the binary anyway.

The solution is a **call-through hook**: let the original method execute completely (computing the cdhash), then override only the return value:

```
validateWithError: dispatches to hook
         │
    ┌────▼────────────────────────────┐
    │  1. Call original IMP (via blr) │ ← cdhash gets computed
    │  2. Original returned YES?      │
    │     YES → return YES            │ ← don't interfere with legit apps
    │     NO  → check binary path     │
    │       path in allowlist → YES   │ ← bypass
    │       not in allowlist  → NO    │ ← reject as normal
    └─────────────────────────────────┘
```

### Dealing with arm64e PAC

`amfid` runs as an arm64e process. The ObjC message dispatch (`objc_msgSend`) uses `braa` (authenticated branch) — if the IMP pointer isn't PAC-signed, the CPU zeros it out and the process crashes at `0x0`.

We solve this by executing `paciza` on our code page address **inside amfid's context** (via thread hijacking), so the IMP is properly signed before `class_replaceMethod` stores it. Additionally, `method_setImplementation` has cache-invalidation issues with preoptimized shared-cache methods on arm64e, so we use `class_replaceMethod` which handles this correctly.

### The CS_DEBUGGED requirement

Our hook code lives on a `mach_vm_allocate`'d page — it has no code signature. Normally the kernel would refuse to execute unsigned pages in amfid. The `CS_DEBUGGED` flag (set when debugserver attaches) tells the kernel to allow execution of unsigned code pages. This means debugserver must stay attached for the hook to keep working.

### Build-time offset extraction

The hook shellcode accesses ObjC ivar `_code` on the `AMFIPathValidator_macos` instance. This ivar offset is **not hardcoded** — it's extracted at build time by a small ObjC probe (`shellcode/probe_ivar.m`) that loads the AMFI framework and calls `ivar_getOffset()`. The Makefile compiles and runs the probe, caches the result in `build/ivar_offset.mk`, and passes it to both the assembler and C compiler via `-DIVAR_CODE_OFFSET=<value>`. This means `make clean && make` automatically adapts to ivar layout changes across macOS versions.

Similarly, `SLOT_DATA_PAGE_PTR` (the offset of the data-page pointer inside the shellcode) is extracted from `build/hook.o` via `nm` at build time.

## Injection Flow

```
1. Find amfid            proc_listallpids → match "amfid"
2. Get task port         task_for_pid(amfid_pid)
3. Resolve ObjC          dlopen AMFI framework → objc_getClass → method IMP
4. Build remote pages    Allocate code page + data page in amfid
                         Write hook shellcode, API pointers, allowlist
5. Spawn debugserver     Attach to amfid → sets CS_DEBUGGED
6. Thread hijack         RSP protocol: save regs → set pc to setup code
7. Setup code runs       paciza(code_page) → class_replaceMethod → brk
8. Finalize              Read return value → restore regs → resume amfid
```

## Memory Layout

**Data page** (RW) — function pointers and configuration:

| Offset | Content |
|--------|---------|
| `0x08` | Original IMP (written after `class_replaceMethod` returns) |
| `0x10` | `SecCodeCopyPath` pointer |
| `0x18` | `CFURLGetFileSystemRepresentation` pointer |
| `0x20` | `CFRelease` pointer |
| `0x28` | Allowlist byte length |
| `0x30` | Allowlist memory address |

**Code page** (RX) — hook shellcode + setup trampoline:

| Region | Content |
|--------|---------|
| `0x00..N` | Hook entry (`hook.S` — prologue, call-through, path matching) |
| `N+0` | `paciza x2` — PAC-sign the IMP |
| `N+4` | `blr x8` — call `class_replaceMethod` |
| `N+8` | `brk #0xfed6` — trap for injector to regain control |

**Allowlist page** (R) — newline-separated path prefixes, compared against each binary's path via `SecCodeCopyPath`.

## Allowlist

```bash
# CLI flags (preferred)
sudo bin/amfree --path /Users/me/dev/ --path /opt/tools/

# File-based fallback (if no --path given)
echo "/Users/me/dev/" > /tmp/amfid_allowlist
sudo bin/amfree
```

Paths are matched as **prefixes** — a binary at `/Users/me/dev/foo/bar` matches the entry `/Users/me/dev/`.

## Project Structure

```
src/
  main.c             Entry point, argument parsing
  hook_install.c     ObjC resolution, code/data page construction
  debugserver.c      Spawn debugserver, RSP thread hijack
  mach_utils.c       Mach VM primitives (alloc, read, write, protect)
  remote_macho.c     Find amfid PID and method IMP
  rsp.c              GDB Remote Serial Protocol client
shellcode/
  hook.S             ARM64 hook (call-through + prefix matching)
  data_layout.h      Shared data page layout + class name
  probe_ivar.m       Build-time probe for ObjC ivar offsets
include/             Headers
tests/               test_ent with private entitlements
docs/
  dev-errors.md      Development error log (13 issues encountered)
```

## Limitations

- **Does not bypass kernel AMFI** — restricted entitlements requiring Apple signing are rejected by the kernel before amfid is consulted.
- **SIP must be disabled** — `task_for_pid` on system daemons requires root + SIP off.
- **debugserver must stay alive** — killing it removes `CS_DEBUGGED`, and the hook's unsigned code page becomes non-executable.
- **Does not persist across amfid restarts** — reboot or `killall amfid` requires re-injection.

## Acknowledgements

Inspired by [amfidont](https://github.com/zqxwce/amfidont), which demonstrated that amfid's validation can be intercepted via debugserver. amfree takes a different approach — instead of using LLDB breakpoints, it installs a persistent ObjC method swizzle with a call-through hook.
