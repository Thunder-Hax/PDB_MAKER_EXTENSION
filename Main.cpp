// WinDbg extension: !dump2pdb <DumpFolder> <OutFolder>
// Builds placeholder PDB files (metadata only) for each module listed in each .dmp found under <DumpFolder>.
// Exported helpers (implemented later) allow setting the selected folder and triggering analysis without restarting WinDbg.

#include <windows.h>
#include <wdbgexts.h>
#include <dbghelp.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <dbgeng.h>
#include <shobjidl.h>
#include <ole2.h>
#include <urlmon.h>
#include <winhttp.h>
#include <future>
#include <thread>

#pragma comment(lib, "ole32.lib")

#pragma comment(lib, "dbgeng.lib")

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;
static IDebugClient* g_DebugClient = nullptr;
static CRITICAL_SECTION g_ModuleLock;
fs::path g_OutFolderPath;
// track whether we've already shown the folder picker in this process
static bool g_HavePromptedForFolder = false;
static bool g_PromptedForFolder = false;
static bool g_DidPrompt = false;
// atomic guard to ensure folder prompt only once per process
static volatile LONG g_HasPromptedForFolder = 0;
// Temporarily store module bases discovered during init
static std::vector<ULONG64> g_ModuleBases;
// ensure we broadcast analysis only once per process (use atomic Interlocked ops)
static volatile LONG g_HasBroadcastAnalyze = 0;

// Global collection of modules / entries discovered from dumps or live session.
// Exposed as extern-friendly symbol for other translation units if needed.
struct GlobalModule { std::string name; uint64_t base; uint32_t size; std::string guid; uint32_t age = 0; };
extern std::vector<GlobalModule> g_DumpModules;
std::vector<GlobalModule> g_DumpModules;

// Forward declarations for helper functions implemented later in this file
// forward-declare consolidated log writer
static void WriteConsolidatedLog(const fs::path &outRoot);
// write consolidated log removed; extension now only broadcasts '!analyze -v' on load
static std::wstring GuidForSymbolPath(const std::wstring& guidStr);
static bool TryDownloadPdbFromSymbolServers(const std::wstring& pdbName, const std::wstring& guidW, uint32_t age, const fs::path& destPath);

// (no UI) helper removed

// Read CodeView RSDS info (pdb name, guid, age) from an image file. Returns true if found.
static bool ReadCodeViewInfo(const std::wstring& imagePath, std::wstring& pdbNameOut, std::wstring& guidOut, uint32_t& ageOut)
{
    pdbNameOut.clear(); guidOut.clear(); ageOut = 0;
    HANDLE hFile = CreateFileW(imagePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return false; }
    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return false; }
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile); return false; }
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile); return false; }
    IMAGE_DATA_DIRECTORY dbgDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!dbgDir.VirtualAddress || !dbgDir.Size) { UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile); return false; }
    auto debug = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>((BYTE*)base + dbgDir.VirtualAddress);
    SIZE_T count = dbgDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    bool found = false;
    for (SIZE_T di = 0; di < count; ++di) {
        if (debug[di].Type == IMAGE_DEBUG_TYPE_CODEVIEW && debug[di].PointerToRawData) {
            BYTE* cv = reinterpret_cast<BYTE*>((BYTE*)base + debug[di].PointerToRawData);
            if (memcmp(cv, "RSDS", 4) == 0) {
                BYTE* p = cv + 4;
                GUID guid;
                memcpy(&guid, p, sizeof(GUID)); p += 16;
                DWORD a = *(DWORD*)p; p += 4;
                char* name = reinterpret_cast<char*>(p);
                if (name) {
                    int l = MultiByteToWideChar(CP_ACP, 0, name, -1, NULL, 0);
                    if (l > 0) { pdbNameOut.resize(l - 1); MultiByteToWideChar(CP_ACP, 0, name, -1, &pdbNameOut[0], l); }
                }

                // Convert GUID to string
                WCHAR gws[64] = { 0 };
                if (StringFromGUID2(guid, gws, _countof(gws))) {
                    guidOut.assign(gws);
                }
                ageOut = a;
                found = true;
                break;
            }
        }
    }
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return found;
}


// No command execution helpers in headless mode.
// UI removed: no window procedure

static void AppendLog(const std::string& entry)
{
    // append to a log file in the selected output folder if available, otherwise temp
    fs::path logPath;
    if (!g_OutFolderPath.empty()) {
        logPath = g_OutFolderPath / "pdb_maker_extension.log";
        std::error_code ec;
        fs::create_directories(g_OutFolderPath, ec);
        // ignore ec here
    }
    else {
        char tempPath[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempPath) == 0) return;
        logPath = fs::path(std::string(tempPath)) / "pdb_maker_extension.log";
    }
    std::ofstream ofs(logPath.string(), std::ios::app);
    if (!ofs) return;
    ofs << entry << "\n";
}

// Append entries specifically for reconstructed placeholder PDBs into a consolidated pdblog.log
static void AppendPdblog(const std::string& entry)
{
    fs::path logPath;
    if (!g_OutFolderPath.empty()) {
        logPath = g_OutFolderPath / "pdblog.log";
        std::error_code ec;
        fs::create_directories(g_OutFolderPath, ec);
        // ignore ec here
    }
    else {
        char tempPath[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tempPath) == 0) return;
        logPath = fs::path(std::string(tempPath)) / "pdblog.log";
    }
    std::ofstream ofs(logPath.string(), std::ios::app);
    if (!ofs) return;
    ofs << entry << "\n";
}
// no UI thread

// Implement exported helpers below (defined after other functions)


// Implement exported helpers below (defined after other functions)


// No exported helpers (extension only broadcasts '!analyze -v' on load)


// No UI callbacks
static std::string WideToUtf8(const std::wstring& ws)
{
    if (ws.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, NULL, NULL);
    if (len <= 0) return std::string();
    std::string s;
    s.resize(len - 1);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &s[0], len, NULL, NULL);
    return s;
}

// Forward declaration so RunDllEntry can call it
static void DoDumpDir2Pdb(const std::wstring& dumpFolderW, const std::wstring& outFolderW);

// No exported RunDllEntry: extension runs automatically on load.

// Extension API version
EXT_API_VERSION g_ExtApiVersion = { 1, 0, EXT_API_VERSION_NUMBER64, 0 };
WINDBG_EXTENSION_APIS ExtensionApis;

extern "C" __declspec(dllexport) LPEXT_API_VERSION ExtensionApiVersion(void)
{
    return &g_ExtApiVersion;
}

// WideToUtf8 defined earlier

extern "C" __declspec(dllexport) VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT MajorVersion, USHORT MinorVersion)
{
    ExtensionApis = *lpExtensionApis;

    // Broadcast '!analyze -v' once (race-free)
    if (InterlockedCompareExchange(&g_HasBroadcastAnalyze, 1, 0) == 0) {
        IDebugClient* client = nullptr;
        if (DebugCreate(__uuidof(IDebugClient), (void**)&client) == S_OK && client) {
            IDebugControl* ctrl = nullptr;
            if (client->QueryInterface(__uuidof(IDebugControl), (void**)&ctrl) == S_OK && ctrl) {
                dprintf("PDB_MAKER_EXTENSION: Broadcasting '!analyze -v' on load\n");
                ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "!analyze -v", DEBUG_EXECUTE_DEFAULT);
                ctrl->Release();
            }
            client->Release();
        }
    }

    // Try to prompt for a folder and generate PDBs on load.
    // If an interactive desktop is not available, fall back to a default folder.
    auto HasInteractiveDesktop = []() -> bool {
        HDESK hDesk = OpenInputDesktop(0, FALSE, READ_CONTROL);
        if (!hDesk) return false;
        CloseDesktop(hDesk);
        return true;
    };

    std::wstring outFolder;
    // Prompt only once per process. If already prompted, reuse the stored folder or default.
    if (InterlockedCompareExchange(&g_HasPromptedForFolder, 1, 0) == 0) {
        if (HasInteractiveDesktop()) {
            HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
            bool coInit = SUCCEEDED(hr);
            IFileDialog* pfd = nullptr;
            if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd)))) {
                DWORD options = 0;
                if (SUCCEEDED(pfd->GetOptions(&options))) pfd->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
                pfd->SetTitle(L"Select output symbols folder (PDBs will be written here)");
                if (SUCCEEDED(pfd->Show(NULL))) {
                    IShellItem* psi = nullptr;
                    if (SUCCEEDED(pfd->GetResult(&psi)) && psi) {
                        PWSTR pszPath = nullptr;
                        if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &pszPath)) && pszPath) {
                            outFolder = pszPath;
                            CoTaskMemFree(pszPath);
                        }
                        psi->Release();
                    }
                }
                pfd->Release();
            }
            if (coInit) CoUninitialize();
        }
        else {
            // no interactive desktop: use default folder
            outFolder = L"C:\\RebuiltSymbols";
            dprintf("PDB_MAKER_EXTENSION: No interactive desktop; using default folder %S\n", outFolder.c_str());
        }

        if (!outFolder.empty()) {
            g_OutFolderPath = fs::path(outFolder);
        }
    }
    else {
        // Already prompted in this process: reuse previously selected folder or default
        if (!g_OutFolderPath.empty()) outFolder = g_OutFolderPath.wstring();
        else {
            outFolder = L"C:\\RebuiltSymbols";
            dprintf("PDB_MAKER_EXTENSION: Reusing default folder %S\n", outFolder.c_str());
            g_OutFolderPath = fs::path(outFolder);
        }
    }

    if (outFolder.empty()) {
        dprintf("PDB_MAKER_EXTENSION: No folder chosen on load; automatic generation cancelled.\n");
        return;
    }

    dprintf("PDB_MAKER_EXTENSION: Selected output folder on load: %S\n", outFolder.c_str());

    // remember chosen output folder for logging
    g_OutFolderPath = fs::path(outFolder);

    // Launch live-session PDB generation after analyze in a background thread.
    // This ensures analyze runs first, then we prompt and perform symbol work.
    try {
        std::wstring captureOut = outFolder;
        std::thread([captureOut]() {
            // The body below mirrors the previous live-session generation logic.
            IDebugClient* client2 = nullptr;
            if (DebugCreate(__uuidof(IDebugClient), (void**)&client2) != S_OK || !client2) {
                dprintf("PDB_MAKER_EXTENSION: Failed to create IDebugClient for background generation.\n");
                return;
            }
            IDebugSymbols* symbols2 = nullptr;
            if (client2->QueryInterface(__uuidof(IDebugSymbols), (void**)&symbols2) != S_OK || !symbols2) {
                dprintf("PDB_MAKER_EXTENSION: Failed to get IDebugSymbols for background generation.\n");
                client2->Release();
                return;
            }

            // keep the client for possible use
            g_DebugClient = client2;
            InitializeCriticalSection(&g_ModuleLock);

            std::vector<ULONG64> moduleBases;
            for (ULONG idx = 0;; ++idx) {
                ULONG64 base = 0;
                if (symbols2->GetModuleByIndex(idx, &base) != S_OK) break;
                moduleBases.push_back(base);
            }

            std::error_code ec2;
            fs::create_directories(captureOut, ec2);
            if (ec2) {
                dprintf("PDB_MAKER_EXTENSION: Failed to create output folder: %s\n", WideToUtf8(captureOut).c_str());
                symbols2->Release(); client2->Release();
                return;
            }

            HANDLE hProc = GetCurrentProcess();
            SymSetOptions(SymGetOptions() | SYMOPT_DEFERRED_LOADS);
            if (!SymInitializeW(hProc, NULL, FALSE)) {
                dprintf("PDB_MAKER_EXTENSION: SymInitialize failed (will still attempt local copies)\n");
            } else {
                char* sp = nullptr; size_t spLen = 0;
                if (_dupenv_s(&sp, &spLen, "_NT_SYMBOL_PATH") == 0 && sp && spLen > 0) {
                    int l = MultiByteToWideChar(CP_ACP, 0, sp, -1, NULL, 0);
                    if (l > 0) {
                        std::wstring wsp; wsp.resize(l - 1);
                        MultiByteToWideChar(CP_ACP, 0, sp, -1, &wsp[0], l);
                        SymSetSearchPathW(hProc, wsp.c_str());
                    }
                    free(sp);
                }
            }

            auto ReadPdbNameFromImage2 = [&](const std::wstring &imagePath)->std::wstring {
                HANDLE hFile = CreateFileW(imagePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile == INVALID_HANDLE_VALUE) return std::wstring();
                HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
                if (!hMap) { CloseHandle(hFile); return std::wstring(); }
                LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
                if (!base) { CloseHandle(hMap); CloseHandle(hFile); return std::wstring(); }

                auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
                std::wstring res;
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)base + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE) {
                        IMAGE_DATA_DIRECTORY dbgDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
                        if (dbgDir.VirtualAddress && dbgDir.Size) {
                            auto debug = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>((BYTE*)base + dbgDir.VirtualAddress);
                            SIZE_T count = dbgDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
                            for (SIZE_T di = 0; di < count; ++di) {
                                if (debug[di].Type == IMAGE_DEBUG_TYPE_CODEVIEW && debug[di].PointerToRawData) {
                                    BYTE* cv = reinterpret_cast<BYTE*>((BYTE*)base + debug[di].PointerToRawData);
                                    if (memcmp(cv, "RSDS", 4) == 0) {
                                        BYTE* p = cv + 24;
                                        char* name = reinterpret_cast<char*>(p);
                                        if (name) {
                                            int l = MultiByteToWideChar(CP_ACP, 0, name, -1, NULL, 0);
                                            if (l > 0) { res.resize(l - 1); MultiByteToWideChar(CP_ACP, 0, name, -1, &res[0], l); }
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                UnmapViewOfFile(base);
                CloseHandle(hMap);
                CloseHandle(hFile);
                return res;
            };

            for (ULONG i = 0; i < (ULONG)moduleBases.size(); ++i) {
                ULONG64 base = moduleBases[i];
                char imageName[1024] = {0};
                char moduleName[512] = {0};
                char loadedName[1024] = {0};
                ULONG imageNameSize = 0, moduleNameSize = 0, loadedNameSize = 0;
                symbols2->GetModuleNames(i, base, imageName, sizeof(imageName), &imageNameSize,
                                         moduleName, sizeof(moduleName), &moduleNameSize,
                                         loadedName, sizeof(loadedName), &loadedNameSize);
                int len = MultiByteToWideChar(CP_ACP, 0, moduleName, -1, nullptr, 0);
                std::wstring wmod;
                if (len > 0) { wmod.resize(len - 1); MultiByteToWideChar(CP_ACP, 0, moduleName, -1, &wmod[0], len); }
                if (wmod.empty()) {
                    len = MultiByteToWideChar(CP_ACP, 0, imageName, -1, nullptr, 0);
                    if (len > 0) { wmod.resize(len - 1); MultiByteToWideChar(CP_ACP, 0, imageName, -1, &wmod[0], len); }
                }
                if (wmod.empty()) wmod = L"unknown_module";

                fs::path outPdbPath = fs::path(captureOut) / (fs::path(wmod).stem().wstring() + L".pdb");
                dprintf("PDB_MAKER_EXTENSION: Locating real PDB for %S...\n", wmod.c_str());

                std::wstring pdbName;
                std::wstring guidW; uint32_t guidAge = 0;
                if (loadedName[0]) {
                    int llen = MultiByteToWideChar(CP_ACP, 0, loadedName, -1, nullptr, 0);
                    if (llen > 0) {
                        std::wstring loadedW; loadedW.resize(llen - 1);
                        MultiByteToWideChar(CP_ACP, 0, loadedName, -1, &loadedW[0], llen);
                        std::wstring pdbFromImage;
                        if (ReadCodeViewInfo(loadedW, pdbFromImage, guidW, guidAge)) {
                            pdbName = pdbFromImage;
                        } else {
                            pdbName = ReadPdbNameFromImage2(loadedW);
                        }
                        if (!pdbName.empty()) {
                            fs::path candidate = fs::path(loadedW).remove_filename() / pdbName;
                            if (fs::exists(candidate)) {
                                std::error_code copyec;
                                fs::copy_file(candidate, outPdbPath, fs::copy_options::overwrite_existing, copyec);
                                if (!copyec) { dprintf("  Copied from image dir: %s\n", WideToUtf8(outPdbPath.wstring()).c_str()); continue; }
                            }
                        }
                    }
                }

                if (pdbName.empty()) {
                    pdbName = fs::path(wmod).filename().wstring();
                    pdbName = fs::path(pdbName).stem().wstring();
                    pdbName += L".pdb";
                }

                WCHAR found[MAX_PATH] = {0};
                bool copied = false;
                if (SymFindFileInPathW(hProc, NULL, pdbName.c_str(), NULL, 0, 0, 0, found, NULL, NULL)) {
                    std::error_code copyec;
                    fs::copy_file(found, outPdbPath, fs::copy_options::overwrite_existing, copyec);
                    if (!copyec) { dprintf("  Found via symbol path: %s\n", WideToUtf8(outPdbPath.wstring()).c_str()); copied = true; }
                    if (!copyec) {
                        AppendLog(std::string("Copied from symbol path: ") + WideToUtf8(outPdbPath.wstring()));
                    }
                }

                if (!copied && !guidW.empty()) {
                    if (TryDownloadPdbFromSymbolServers(pdbName, guidW, guidAge, outPdbPath)) {
                        dprintf("  Downloaded via symbol server: %s\n", WideToUtf8(outPdbPath.wstring()).c_str());
                        AppendLog(std::string("Downloaded from symbol server: ") + WideToUtf8(outPdbPath.wstring()));
                        copied = true;
                    }
                }

                GlobalModule gm; gm.name = WideToUtf8(wmod); gm.base = base; gm.size = 0; gm.guid = ""; gm.age = 0;
                if (!guidW.empty()) { gm.guid = WideToUtf8(guidW); gm.age = guidAge; }
                EnterCriticalSection(&g_ModuleLock);
                g_DumpModules.push_back(gm);
                LeaveCriticalSection(&g_ModuleLock);

                if (!copied) {
                    dprintf("  No real PDB found for %s; skipping creation of placeholder file\n", WideToUtf8(outPdbPath.wstring()).c_str());
                    std::string line = "Reconstructed placeholder PDB for module: " + WideToUtf8(wmod) + " Base: 0x";
                    {
                        std::ostringstream oss;
                        oss << std::hex << base;
                        line += oss.str();
                    }
                    line += " Source: live debug session (placeholder)";
                    AppendPdblog(line);
                }
            }

            SymCleanup(hProc);
            symbols2->Release(); client2->Release();
            dprintf("PDB_MAKER_EXTENSION: Automatic generation on load completed.\n");
            WriteConsolidatedLog(g_OutFolderPath);
        }).detach();
    }
    catch (...) {
        // ignore thread launch failures
    }
}

extern "C" __declspec(dllexport) VOID WinDbgExtensionDllUninit(void)
{
    // Release debug client if we held it
    if (g_DebugClient) {
        g_DebugClient->Release();
        g_DebugClient = nullptr;
    }
    // cleanup module lock
    DeleteCriticalSection(&g_ModuleLock);
}


// Core implementation: enumerate dumps in dumpFolder and write placeholder PDBs into outFolder
static void DoDumpDir2Pdb(const std::wstring& dumpFolderW, const std::wstring& outFolderW)
{
    // ensure global log target matches the outFolder used for this operation
    g_OutFolderPath = fs::path(outFolderW);

    std::string dumpFolderA = WideToUtf8(dumpFolderW);
    std::string outFolderA = WideToUtf8(outFolderW);
    dprintf("Dump folder: %s\n", dumpFolderA.c_str());
    dprintf("Output symbols folder: %s\n", outFolderA.c_str());

    std::error_code ec;
    if (!fs::exists(dumpFolderW, ec) || !fs::is_directory(dumpFolderW, ec)) {
        dprintf("Dump folder does not exist or is not a directory: %s\n", dumpFolderA.c_str());
        return;
    }

    fs::create_directories(outFolderW, ec);
    if (ec) {
        dprintf("Failed to create output folder: %s (%s)\n", outFolderA.c_str(), ec.message().c_str());
        return;
    }

    size_t dumpsFound = 0;
    for (auto& entry : fs::directory_iterator(dumpFolderW)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().wstring();
        if (ext != L".dmp" && ext != L".DMP") continue;
        ++dumpsFound;
        auto dumpPath = entry.path();
        std::wstring dumpStem = dumpPath.stem().wstring();
        fs::path dumpOut = fs::path(outFolderW) / dumpStem;
        fs::create_directories(dumpOut, ec);
        if (ec) { dprintf("Failed to create folder for dump: %s (%s)\n", WideToUtf8(dumpOut.wstring()).c_str(), ec.message().c_str()); continue; }
        dprintf("Processing dump: %s -> %s\n", WideToUtf8(dumpPath.filename().wstring()).c_str(), WideToUtf8(dumpOut.wstring()).c_str());

        struct ModuleInfo { std::wstring name; uint64_t base; uint32_t size; std::wstring guid; uint32_t age; };
        std::vector<ModuleInfo> modules;

        HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
            if (hMap) {
                LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
                if (base) {
                    PMINIDUMP_DIRECTORY dir = nullptr;
                    PVOID stream = nullptr;
                    ULONG streamSize = 0;
                    if (MiniDumpReadDumpStream(base, ModuleListStream, &dir, &stream, &streamSize) && stream) {
                        auto modList = reinterpret_cast<PMINIDUMP_MODULE_LIST>(stream);
                        for (ULONG i = 0; i < modList->NumberOfModules; ++i) {
                            const MINIDUMP_MODULE& m = modList->Modules[i];
                            std::wstring modName;
                            if (m.ModuleNameRva != 0) {
                                auto pStr = reinterpret_cast<PMINIDUMP_STRING>(reinterpret_cast<uint8_t*>(base) + m.ModuleNameRva);
                                if (pStr && pStr->Length > 0) {
                                    modName.assign(pStr->Buffer, pStr->Buffer + pStr->Length / sizeof(WCHAR));
                                }
                            }
                            if (modName.empty()) modName = L"unknown_module";
                            std::wstring modGuid; uint32_t modAge = 0;
                            // try to read CodeView info from the dump's module CvRecord if present
                            if (m.CvRecord.Rva != 0 && m.CvRecord.DataSize > 0) {
                                BYTE* cv = reinterpret_cast<BYTE*>(base) + m.CvRecord.Rva;
                                if (cv && memcmp(cv, "RSDS", 4) == 0) {
                                    BYTE* p = cv + 4;
                                    GUID guid; memcpy(&guid, p, sizeof(GUID)); p += 16;
                                    DWORD a = *(DWORD*)p; p += 4;
                                    char* name = reinterpret_cast<char*>(p);
                                    WCHAR gws[64] = { 0 };
                                    if (StringFromGUID2(guid, gws, _countof(gws))) modGuid.assign(gws);
                                    modAge = a;
                                }
                            }
                            modules.push_back({ modName, m.BaseOfImage, m.SizeOfImage, modGuid, modAge });
                            // add to global module list
                            GlobalModule gm; gm.name = WideToUtf8(modName); gm.base = m.BaseOfImage; gm.size = m.SizeOfImage; gm.guid = ""; gm.age = 0;
                            if (!modGuid.empty()) { gm.guid = WideToUtf8(modGuid); gm.age = modAge; }
                            EnterCriticalSection(&g_ModuleLock);
                            g_DumpModules.push_back(gm);
                            LeaveCriticalSection(&g_ModuleLock);
                        }
                    }
                    UnmapViewOfFile(base);
                }
                CloseHandle(hMap);
            }
            CloseHandle(hFile);
        }

        if (modules.empty()) {
            dprintf("  No modules found in dump %s\n", WideToUtf8(dumpPath.filename().wstring()).c_str());
        }

        // Export module list and helper scripts into the dump output folder
        try {
            fs::path listPath = dumpOut / "modules_list.txt";
            std::ofstream listOf(listPath);
            if (listOf) {
                listOf << "Name,Base,Size\n";
                for (auto& m : modules) {
                    listOf << WideToUtf8(m.name) << ",0x" << std::hex << m.base << std::dec << "," << m.size << "\n";
                }
                listOf.close();
                dprintf("  Wrote module list: %s\n", WideToUtf8(listPath.wstring()).c_str());
            }

            fs::path cmdPath = dumpOut / "windbg_commands.txt";
            std::ofstream cmdOf(cmdPath);
            if (cmdOf) {
                cmdOf << "!analyze -v\n";
                cmdOf << "lm\n";
                cmdOf << "lmv\n";
                for (auto& m : modules) {
                    cmdOf << "lmvm " << WideToUtf8(m.name) << "\n";
                }
                cmdOf.close();
                dprintf("  Wrote WinDbg command list: %s\n", WideToUtf8(cmdPath.wstring()).c_str());
            }

            // simple batch script to attempt symbol download using symchk (if available)
            fs::path batPath = dumpOut / "download_symbols.bat";
            std::ofstream bat(batPath);
            if (bat) {
                bat << "@echo off\n";
                bat << "rem Attempt to download symbols for modules listed in this dump\n";
                bat << "set SYMSRV=srv*C:\\symcache*https://msdl.microsoft.com/download/symbols\n";
                for (auto& m : modules) {
                    bat << "echo Downloading symbols for " << WideToUtf8(m.name) << "\n";
                    bat << "if exist %windir%\\system32\\symchk.exe ( symchk /r " << WideToUtf8(m.name) << " /s %SYMSRV% ) else ( echo symchk not found )\n";
                }
                bat.close();
                dprintf("  Wrote helper script: %s\n", WideToUtf8(batPath.wstring()).c_str());
            }
        }
        catch (...) {
            dprintf("  Failed to write dump helper files for %s\n", WideToUtf8(dumpOut.wstring()).c_str());
        }

        for (auto& mi : modules) {
            fs::path modPath(mi.name);
            fs::path pdbName = modPath.stem(); pdbName += L".pdb";
            fs::path pdbPath = dumpOut / pdbName;
            std::ofstream ofs(pdbPath, std::ios::binary);
            if (!ofs) { dprintf("  Failed to create %s\n", WideToUtf8(pdbPath.wstring()).c_str()); continue; }
            std::string line = "Reconstructed placeholder PDB for module: " + WideToUtf8(mi.name);
            {
                std::ostringstream oss;
                oss << " Base: 0x" << std::hex << mi.base << std::dec << " Size: " << mi.size;
                line += oss.str();
            }
            line += " Source dump: "; line += WideToUtf8(dumpPath.wstring());
            ofs << line;
            ofs.close();
            dprintf("  Created: %s\n", WideToUtf8(pdbPath.wstring()).c_str());
            AppendLog(line);
        }
    }

    if (dumpsFound == 0) dprintf("No .dmp files found in %s\n", WideToUtf8(dumpFolderW).c_str());
    else dprintf("All placeholder PDBs saved under: %s\n", WideToUtf8(outFolderW).c_str());
    // write consolidated log for dumps output (removed - extension only broadcasts '!analyze -v')
}

// (Command handlers removed — extension runs automatically on load)

// Consolidated log writer
static void WriteConsolidatedLog(const fs::path &outRoot)
{
    if (outRoot.empty()) return;
    std::error_code ec;
    fs::path logFile = outRoot / "all_pdbs.log";
    std::ofstream ofs(logFile, std::ios::trunc);
    if (!ofs) return;
    ofs << "PDB Summary\n";
    ofs << "Root: " << WideToUtf8(outRoot.wstring()) << "\n\n";
    for (auto &p : fs::recursive_directory_iterator(outRoot, ec)) {
        if (ec) break;
        if (!p.is_regular_file()) continue;
        if (p.path().extension() != L".pdb") continue;
        uint64_t sz = 0;
        auto fsz = fs::file_size(p.path(), ec);
        if (!ec) sz = (uint64_t)fsz;
        std::string type = "real/unknown";
        std::ifstream ifs(p.path(), std::ios::binary);
        if (ifs) {
            std::string head;
            head.resize(512);
            ifs.read(&head[0], (std::streamsize)head.size());
            std::streamsize r = ifs.gcount();
            if (r > 0) head.resize((size_t)r);
            if (head.find("Reconstructed placeholder") != std::string::npos) type = "placeholder";
        }
        ofs << WideToUtf8(p.path().wstring()) << ", size=" << sz << ", type=" << type << "\n";
    }
    ofs.close();
}

// Normalize GUID string "{XXXXXXXX-XXXX-...}" -> "XXXXXXXX..." (uppercase, no braces/dashes)

static std::wstring GuidForSymbolPath(const std::wstring& guidStr)
{
    std::wstring out;
    for (wchar_t c : guidStr) {
        if (c == L'{' || c == L'}' || c == L'-') continue;
        if (iswxdigit(c)) out.push_back(towupper(c));
    }
    return out;
}

// Trim helpers
static inline std::string TrimAscii(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace((unsigned char)s[a])) ++a;
    while (b > a && isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static inline std::wstring ToW(const std::string& s) {
    int l = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    if (l <= 0) return std::wstring();
    std::wstring ws; ws.resize(l - 1);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], l);
    return ws;
}

// Read a simple list file and attempt to build real PDBs for each entry.
// Input format (one entry per line):
//   <modulePathOrName> [GUID] [Age] [Address]
// Examples:
//   EOSSDK_Win64_Shipping_1_17_1_3.dll {GUID} 1 0x7fff84b60000
//   someModule.dll
static void BuildPdbsFromList(const fs::path& listFile, const fs::path& outFolder)
{
    std::error_code ec;
    if (!fs::exists(listFile, ec)) { AppendLog(std::string("List file not found: ") + listFile.string()); return; }
    fs::create_directories(outFolder, ec);

    std::ifstream ifs(listFile.string());
    if (!ifs) { AppendLog(std::string("Failed to open list file: ") + listFile.string()); return; }

    std::string line; size_t lineNo = 0;
    HANDLE hProc = GetCurrentProcess();
    while (std::getline(ifs, line)) {
        ++lineNo;
        std::string t = TrimAscii(line);
        if (t.empty() || t[0] == '#') continue;
        std::istringstream iss(t);
        std::vector<std::string> toks; std::string tok;
        while (iss >> tok) toks.push_back(tok);
        if (toks.empty()) continue;

        std::string modStr = toks[0];
        std::wstring wmod = ToW(modStr);
        std::wstring guidW; uint32_t age = 0; std::string addr;
        for (size_t i = 1; i < toks.size(); ++i) {
            std::string s = toks[i];
            bool hasBrace = (s.find('{') != std::string::npos || s.find('}') != std::string::npos);
            bool hasDash = (s.find('-') != std::string::npos);
            bool isHexLike = true; for (char c : s) if (!(isxdigit((unsigned char)c) || c == '{' || c == '}' || c == '-')) { isHexLike = false; break; }
            if ((hasBrace || hasDash) && isHexLike) { guidW = ToW(s); continue; }
            bool allDigits = !s.empty(); for (char c : s) if (!isdigit((unsigned char)c)) { allDigits = false; break; }
            if (allDigits) { try { age = (uint32_t)std::stoul(s); } catch (...) {} continue; }
            addr = s;
        }

        fs::path pdbName = fs::path(wmod).stem(); pdbName += L".pdb";
        fs::path outPdb = outFolder / pdbName;
        bool got = false;

        // 1) SymFindFileInPath
        WCHAR found[MAX_PATH] = { 0 };
        if (SymFindFileInPathW(hProc, NULL, pdbName.c_str(), NULL, 0, 0, 0, found, NULL, NULL)) {
            std::error_code copyec;
            fs::copy_file(found, outPdb, fs::copy_options::overwrite_existing, copyec);
            if (!copyec) { AppendLog(std::string("Copied from symbol path: ") + WideToUtf8(outPdb.wstring())); got = true; }
        }

        // 2) Try GUID+age download
        if (!got && !guidW.empty()) {
            if (TryDownloadPdbFromSymbolServers(pdbName.filename().wstring(), guidW, age, outPdb)) {
                AppendLog(std::string("Downloaded from symbol server: ") + WideToUtf8(outPdb.wstring())); got = true;
            }
        }

        // 3) If modStr is a path, try reading CodeView info and copy local PDB
        if (!got) {
            fs::path modPath(modStr);
            if (fs::exists(modPath)) {
                std::wstring pdbFromImage, guidFromImage; uint32_t ageFromImage = 0;
                if (ReadCodeViewInfo(modPath.wstring(), pdbFromImage, guidFromImage, ageFromImage)) {
                    if (!pdbFromImage.empty()) {
                        fs::path candidate = modPath.remove_filename() / pdbFromImage;
                        if (fs::exists(candidate)) {
                            std::error_code copyec;
                            fs::copy_file(candidate, outPdb, fs::copy_options::overwrite_existing, copyec);
                            if (!copyec) { AppendLog(std::string("Copied from image dir: ") + WideToUtf8(outPdb.wstring())); got = true; }
                        }
                    }
                }
            }
        }

        // 3b) If we have an address provided and still not got the PDB, try to resolve the module
        // at that address using the symbol API and then obtain the PDB from the module image or symbol path.
        if (!got && !addr.empty()) {
            uint64_t addrVal = 0;
            try {
                // allow hex (0x...) or plain decimal
                if (addr.size() > 2 && addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) addrVal = std::stoull(addr, nullptr, 16);
                else addrVal = std::stoull(addr, nullptr, 0);
            }
            catch (...) { addrVal = 0; }

            if (addrVal != 0) {
                IMAGEHLP_MODULE64 modInfo;
                memset(&modInfo, 0, sizeof(modInfo));
                modInfo.SizeOfStruct = sizeof(modInfo);
                if (SymGetModuleInfo64(hProc, (DWORD64)addrVal, &modInfo)) {
                    // prefer the fully qualified image name if present
                    const char* imageNameA = (modInfo.LoadedImageName && modInfo.LoadedImageName[0]) ? modInfo.LoadedImageName : modInfo.ImageName;
                    if (imageNameA && imageNameA[0]) {
                        int l = MultiByteToWideChar(CP_ACP, 0, imageNameA, -1, NULL, 0);
                        std::wstring imagePathW;
                        if (l > 0) { imagePathW.resize(l - 1); MultiByteToWideChar(CP_ACP, 0, imageNameA, -1, &imagePathW[0], l); }

                        // try reading CodeView info from the resolved image
                        std::wstring pdbFromImage, guidFromImage; uint32_t ageFromImage = 0;
                        if (ReadCodeViewInfo(imagePathW, pdbFromImage, guidFromImage, ageFromImage) && !pdbFromImage.empty()) {
                            fs::path candidate = fs::path(imagePathW).remove_filename() / pdbFromImage;
                            if (fs::exists(candidate)) {
                                std::error_code copyec;
                                fs::copy_file(candidate, outPdb, fs::copy_options::overwrite_existing, copyec);
                                if (!copyec) { AppendLog(std::string("Copied from image dir (addr resolution): ") + WideToUtf8(outPdb.wstring())); got = true; }
                            }
                        }

                        // if still not found, try SymFindFileInPath using the pdb name derived from the image
                        if (!got) {
                            fs::path modP(imagePathW);
                            fs::path derivedPdb = modP.stem(); derivedPdb += L".pdb";
                            WCHAR found2[MAX_PATH] = { 0 };
                            if (SymFindFileInPathW(hProc, NULL, derivedPdb.c_str(), NULL, 0, 0, 0, found2, NULL, NULL)) {
                                std::error_code copyec;
                                fs::copy_file(found2, outPdb, fs::copy_options::overwrite_existing, copyec);
                                if (!copyec) { AppendLog(std::string("Copied from symbol path (addr resolution): ") + WideToUtf8(outPdb.wstring())); got = true; }
                            }
                        }
                    }
                }
            }
        }

        // 4) failed: append to pdblog
        if (!got) {
            std::string recon = "Reconstructed placeholder PDB for module: " + WideToUtf8(wmod) + " Base: ";
            recon += addr.empty() ? "0x0" : addr;
            recon += " Source: list input (placeholder)";
            AppendPdblog(recon);
            AppendLog(std::string("Failed to obtain PDB for entry (line ") + std::to_string(lineNo) + "): " + modStr);
        }
    }
    AppendLog(std::string("BuildPdbsFromList completed for: ") + listFile.string());
}

extern "C" __declspec(dllexport) void BuildPdbsFromListWrapper(LPCWSTR listFileW, LPCWSTR outFolderW)
{
    if (!listFileW || !outFolderW) return;
    BuildPdbsFromList(fs::path(listFileW), fs::path(outFolderW));
}

// Download a URL into a file using WinHTTP (follows redirects implicitly)
static bool DownloadUrlToFileWinHttp(const std::wstring& url, const fs::path& dest, DWORD timeoutMs = 30000)
{
    URL_COMPONENTS uc;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    // request host and path lengths
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;
    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return false;

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    INTERNET_PORT port = uc.nPort;
    bool secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(L"PDBMaker/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    WinHttpSetTimeouts(hRequest, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!sent) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    if (!WinHttpReceiveResponse(hRequest, NULL)) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    DWORD status = 0; DWORD statusLen = sizeof(status);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusLen, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    std::ofstream ofs(dest, std::ios::binary);
    if (!ofs) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    const DWORD bufSize = 16384;
    std::vector<char> buffer(bufSize);
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        DWORD toRead = (available < bufSize) ? available : bufSize;
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, &buffer[0], toRead, &read) || read == 0) break;
        ofs.write(&buffer[0], read);
        if (!ofs) break;
    }

    ofs.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}

// Try to download a pdb from known symbol servers using the pdb name and GUID+age signature.
static bool TryDownloadPdbFromSymbolServers(const std::wstring& pdbName, const std::wstring& guidW, uint32_t age, const fs::path& destPath)
{
    if (pdbName.empty() || guidW.empty()) return false;
    std::wstring guidNo = GuidForSymbolPath(guidW);
    if (guidNo.empty()) return false;

    // default known server
    std::vector<std::wstring> servers;
    servers.push_back(L"https://msdl.microsoft.com/download/symbols");

    // parse _NT_SYMBOL_PATH for srv* entries and add servers found there
    char* sp = nullptr; size_t spLen = 0;
    if (_dupenv_s(&sp, &spLen, "_NT_SYMBOL_PATH") == 0 && sp && spLen > 0) {
        std::string s(sp);
        free(sp);
        size_t start = 0;
        while (start < s.size()) {
            size_t pos = s.find(';', start);
            std::string token = s.substr(start, (pos == std::string::npos) ? std::string::npos : pos - start);
            start = (pos == std::string::npos) ? s.size() : pos + 1;
            // look for srv*... pattern
            if (token.rfind("srv*", 0) == 0) {
                // the server url is after the last '*'
                size_t last = token.find_last_of('*');
                if (last != std::string::npos && last + 1 < token.size()) {
                    std::string server = token.substr(last + 1);
                    if (!server.empty()) {
                        int l = MultiByteToWideChar(CP_ACP, 0, server.c_str(), -1, NULL, 0);
                        if (l > 0) {
                            std::wstring ws; ws.resize(l - 1);
                            MultiByteToWideChar(CP_ACP, 0, server.c_str(), -1, &ws[0], l);
                            servers.push_back(ws);
                        }
                    }
                }
            }
            else {
                // if token looks like an http(s) url, add it
                if (token.find("http://") == 0 || token.find("https://") == 0) {
                    int l = MultiByteToWideChar(CP_ACP, 0, token.c_str(), -1, NULL, 0);
                    if (l > 0) {
                        std::wstring ws; ws.resize(l - 1);
                        MultiByteToWideChar(CP_ACP, 0, token.c_str(), -1, &ws[0], l);
                        servers.push_back(ws);
                    }
                }
            }
        }
    }

    // Try each server with retries and useful logging
    for (auto& srv : servers) {
        std::wstring url = srv;
        if (!url.empty() && url.back() == L'/') url.pop_back();

        // folder is GUID (no braces/dashes) + age (decimal)
        std::wstring folder = guidNo + std::to_wstring(age);

        // Construct candidate URL
        std::wstring full = url + L"/" + pdbName + L"/" + folder + L"/" + pdbName;

        // Try a few times with backoff
        const int maxAttempts = 5;
        for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
            AppendLog(std::string("Attempting download from symbol server: ") + WideToUtf8(full));

            // 1) Try URLDownloadToFileW (simple)
            HRESULT hr = URLDownloadToFileW(NULL, full.c_str(), destPath.c_str(), 0, NULL);
            if (SUCCEEDED(hr)) {
                AppendLog(std::string("Successfully downloaded PDB to: ") + WideToUtf8(destPath.wstring()));
                return true;
            }

            // 2) Try WinHTTP download (more robust)
            if (DownloadUrlToFileWinHttp(full, destPath)) {
                AppendLog(std::string("Successfully downloaded PDB (WinHTTP) to: ") + WideToUtf8(destPath.wstring()));
                return true;
            }

            // small backoff before retrying
            Sleep(500 * attempt);
        }
    }

    AppendLog(std::string("Failed to download PDB for: ") + WideToUtf8(pdbName) + " with GUID " + WideToUtf8(guidW));
    return false;
}

