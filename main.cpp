#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <atlbase.h>
#include <dia2.h>
#include <assert.h>
#include <string>
#include <algorithm>
#include <functional>
#include <sstream>
#include "filemapping.h"

static bool LogToDebugger = false;

void Log(LPCWSTR format, ...) {
  WCHAR linebuf[1024];
  va_list v;
  va_start(v, format);
  if (LogToDebugger) {
    StringCbVPrintf(linebuf, sizeof(linebuf), format, v);
    OutputDebugString(linebuf);
  }
  else {
    vwprintf (format, v);
  }
  va_end(v);
}

std::wstring get_filename(const std::wstring path) {
  auto back_slash = path.rfind(L'\\');
  auto name_and_ext = back_slash == std::wstring::npos
                    ? path
                    : path.substr(back_slash + 1);
  auto dot = name_and_ext.rfind(L'.');
  auto name = dot == std::wstring::npos ? name_and_ext
                                        : name_and_ext.substr(0, dot);
  std::replace(name.begin(), name.end(), '.', '_');
  return name;
}

void get_filename_test() {
  assert(get_filename(L"C:\\Windows\\system32\\notepad.exe") == L"notepad");
  assert(get_filename(L"notepad.exe") == L"notepad");
  assert(get_filename(L"C:\\Windows\\System32\\Windows.Storage.ApplicationData.dll")
         == L"Windows_Storage_ApplicationData");
  assert(get_filename(L"notepad") == L"notepad");
  assert(get_filename(L"") == L"");
  assert(get_filename(L"\\") == L"");
  assert(get_filename(L"\\\\") == L"");
}

template<class ST>
class bstream {
private:
  std::stringstream ss_;
  int half_char;

public:
  bstream() : half_char(-1) {}

  void operator << (const ST &line) {
    for (auto c : line) {
      *this << c;
    }
  }

  void operator <<(int c) {
    int h = 0;
    if (c >= '0' && c <= '9')
      h = c - '0';
    else if (c >= 'A' && c <= 'F')
      h = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
      h = c - 'a' + 10;
    else
      return;

    if (half_char < 0) {
      half_char = h;
    }
    else {
      ss_ << static_cast<unsigned char>(half_char << 4 | h);
      half_char = -1;
    }
  }

  std::string get() const {
    return ss_.str();
  }

  void flush() {
    ss_.str("");
    half_char = -1;
  }
};

void bstream_test() {
  const unsigned char expected_output[] = {
    0xE3, 0x83, 0xA4, 0xE3, 0x82, 0xB5, 0xE3, 0x82,
    0xA4, 0xE3, 0x83, 0x9E, 0xE3, 0x82, 0xB7, 0xE3,
    0x82, 0xAB, 0xE3, 0x83, 0xA9, 0xE3, 0x83, 0xA1,
  };
  const char input_data[] =
    "E3 83 A4 E3 82 B5 E3 82\t"
    "a4:e3:83:9e:E3:82:B7:E3\n"
    "82ABe383a9e383A1";
  const wchar_t input_dataw[] =
    L"E3 83 A4 E3 82 B5 E3 82\t"
    L"a4:e3:83:9e:E3:82:B7:E3\n"
    L"82ABe383a9e383A1";

  bstream<std::string> bs;
  bs << input_data;
  auto s = bs.get();
  assert(memcmp(s.data(), expected_output, sizeof(expected_output)) == 0);

  bstream<std::wstring> wbs;
  wbs << input_dataw;
  s = bs.get();
  assert(memcmp(s.data(), expected_output, sizeof(expected_output)) == 0);
}

template <typename F>
HRESULT ExceptionHandler(F danger_call) {
  bool ret = false;
  __try {
    ret = danger_call();
  }
  __except(GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR
           ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
    SetLastError(GetExceptionCode());
  }
  return ret;
}

class PE {
private:
  struct DOS_Header {
    short signature;
    short lastsize;
    short nblocks;
    short nreloc;
    short hdrsize;
    short minalloc;
    short maxalloc;
    short ss;
    short sp;
    short checksum;
    short ip;
    short cs;
    short relocpos;
    short noverlay;
    short reserved1[4];
    short oem_id;
    short oem_info;
    short reserved2[10];
    long  e_lfanew;
  };

  FileMapping mapping_;
  FileMapping::View view_;
  const IMAGE_SECTION_HEADER *code_;

  void Release() {
    code_ = nullptr;
    view_ = FileMapping::View();
    mapping_.Attach(nullptr);
  }

public:
  PE() : code_(nullptr) {}

  ~PE() {
    Release();
  }

  bool Load(LPCWSTR filename) {
    Release();
    if (mapping_.Create(filename,
                        /*sectionName*/nullptr,
                        /*mappingAreaSize*/{0},
                        GENERIC_READ,
                        PAGE_READONLY)) {
      view_ = mapping_.CreateMappedView(FILE_MAP_READ,
                                        /*offset*/0,
                                        /*sizeToMap*/0);
    }
    if (!view_)
      return false;

    ExceptionHandler([&]() {
      DWORD offset = 0;
      auto dos = view_.As<DOS_Header>(offset);
      if (dos->signature != 0x5a4d) {
        Log(L"Bad DOS signature: %04x\n", dos->signature);
        return false;
      }

      offset += dos->e_lfanew;

      auto pe_signature = *view_.As<DWORD>(offset);
      if (pe_signature != 0x4550) {
        Log(L"Bad PE signature: %08x\n", pe_signature);
        return false;
      }
      offset += 4; // PE signature

      auto header = view_.As<IMAGE_FILE_HEADER>(offset);
      offset += sizeof(IMAGE_FILE_HEADER);
      if (header->Machine == IMAGE_FILE_MACHINE_I386) {
        offset += sizeof(IMAGE_OPTIONAL_HEADER32);
      }
      else if (header->Machine == IMAGE_FILE_MACHINE_AMD64) {
        offset += sizeof(IMAGE_OPTIONAL_HEADER64);
      }
      else {
        Log(L"Unsupported architecture.");
        return false;
      }

      static const BYTE dot_text[] = {0x2e, 0x74, 0x65, 0x78,
                                      0x74, 0x00, 0x00, 0x00};
      CHAR section_name[IMAGE_SIZEOF_SHORT_NAME + 1];
      section_name[IMAGE_SIZEOF_SHORT_NAME] = 0;
      for (int i = 0; i < header->NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER *section = view_.As<IMAGE_SECTION_HEADER>(offset);
        memcpy(section_name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
        /*
        Log(L"Section#%02d %-8hs RVA +%08x File +%08x\n",
            i + 1,
            section_name,
            section->VirtualAddress,
            section->PointerToRawData);
        */
        if (memcmp(section->Name, dot_text, sizeof(dot_text)) == 0) {
          code_ = section;
          break;
        }
        offset += sizeof(IMAGE_SECTION_HEADER);
      }
      return true;
    });
    return true;
  }

  void Search(const std::string &needle,
              std::function<void(DWORD)> callback) {
    if (!code_) return;

    Log(L"Start searching...\n");

    ExceptionHandler([&]() {
      auto offset_to_rva = code_->VirtualAddress - code_->PointerToRawData;
      auto section_start = view_.As<BYTE>(code_->PointerToRawData);
      auto section_end = view_.As<BYTE>(code_->PointerToRawData + code_->SizeOfRawData);
      auto needle_start = reinterpret_cast<const unsigned char*>(needle.data());
      auto needle_end = needle_start + needle.size();
      auto it = std::search(section_start,
                            section_end,
                            needle_start,
                            needle_end);
      while (it != section_end) {
        const auto offset = static_cast<DWORD>(it - view_.As<BYTE>(0));
        callback(offset + offset_to_rva);
        it = std::search(it + needle.size(),
                         section_end,
                         needle_start,
                         needle_end);
      }
      return true;
    });
  }
};

class DIACallbacks : public IDiaLoadCallback {
private:
  LONG ref_;
public:
  DIACallbacks() : ref_(1) {}

  // IUnknown

  STDMETHODIMP QueryInterface(REFIID riid,
                              _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppv) {
    static QITAB rgqit[] = {
      QITABENT(DIACallbacks, IDiaLoadCallback),
      { 0 },
    };
    return QISearch(this, rgqit, riid, ppv);
  }

  STDMETHODIMP_(ULONG) AddRef() {
    InterlockedIncrement(&ref_);
    return ref_;
  }

  STDMETHODIMP_(ULONG) Release() {
    ULONG ulRefCount = InterlockedDecrement(&ref_);
    if (ref_ == 0)
      delete this;
    return ulRefCount;
  }

  // IDiaLoadCallback

  STDMETHODIMP NotifyDebugDir(BOOL fExecutable,
                              DWORD cbData,
                              BYTE *pbData) {
    return S_OK;
  }

  STDMETHODIMP NotifyOpenDBG(LPCOLESTR dbgPath,
                             HRESULT resultCode) {
    return S_OK;
  }

  STDMETHODIMP NotifyOpenPDB(LPCOLESTR pdbPath,
                             HRESULT resultCode) {
    return S_OK;
  }

  STDMETHODIMP RestrictRegistryAccess() {
    return S_OK;
  }

  STDMETHODIMP RestrictSymbolServerAccess() {
    return S_OK;
  }
};

void EnumSymbols(LPCWSTR target_module,
                 LPCWSTR symbol_path,
                 const std::string &pattern) {
  PE pe;
  if (!pe.Load(target_module))
    return;

  CComPtr<IDiaSession> session;

  if (symbol_path) {
    CComPtr<IDiaDataSource> dia;
    HRESULT hr = dia.CoCreateInstance(CLSID_DiaSource,
                                      nullptr,
                                      CLSCTX_INPROC_SERVER);
    if (SUCCEEDED(hr)) {
      DIACallbacks callbacks;
      hr = dia->loadDataForExe(target_module, symbol_path, &callbacks);
      if (SUCCEEDED(hr)) {
        hr = dia->openSession(&session);
        if (SUCCEEDED(hr)) {
          ;
        }
        else {
          Log(L"openSession failed - %08x\n", hr);
        }
      }
      else {
        Log(L"loadDataForExe failed - %08x\n", hr);
      }
    }
    else {
      Log(L"CoCreateInstance(CLSID_DiaSource) failed - %08x\n", hr);
    }
  }

  const auto module_name = get_filename(target_module);
  pe.Search(pattern, [&](DWORD rva) {
    BSTR symbol_name = nullptr;
    long displacement = 0;
    if (session) {
      CComPtr<IDiaSymbol> symbol;
      if (SUCCEEDED(session->findSymbolByRVAEx(rva,
                                               SymTagFunction,
                                               &symbol,
                                               &displacement))
          && symbol) {
        symbol->get_name(&symbol_name);
      }
    }

    if (symbol_name) {
      Log(L"+%08x\t%s!%s +%x\n",
          rva,
          module_name.c_str(),
          symbol_name,
          displacement);
    }
    else {
      Log(L"+%08x\n", rva);
    }
  });
}

static std::wstring GetEnv(LPCWSTR variable_name) {
  std::wstring env;
  DWORD required_length = GetEnvironmentVariable(variable_name, nullptr, 0);
  if (auto buf = new wchar_t[required_length]) {
    if (GetEnvironmentVariable(variable_name, buf, required_length)) {
      env = buf;
    }
    delete [] buf;
  }
  return env;
}

int wmain(int argc, wchar_t *argv[]) {
  if (argc >= 3) {
    if (SUCCEEDED(CoInitialize(nullptr))) {
      bstream<std::wstring> bs;
      bs << argv[2];
      const auto pattern_to_search = bs.get();
      const auto symbol_path = GetEnv(L"_NT_SYMBOL_PATH");
      EnumSymbols(argv[1], symbol_path.c_str(), pattern_to_search);
      CoUninitialize();
    }
  }
  else if (argc == 2 && _wcsicmp(argv[1], L"test") == 0) {
    bstream_test();
    get_filename_test();
  }
  else {
    Log(L"USAGE: PESCAN <PE> <pattern>\n\n"
        L"Set _NT_SYMBOL_PATH environment variable to get a symbol name for RVA,\n"
        L"and place symsrv.exe in a directory that is visible from PESCAN.\n\n"
        L"Pattern examples:\n\n"
        L"  <Stack Pivot>\n"
        L"  94:c3 -- xchg eax,esp\n"
        L"           ret\n\n"
        L"  <Get x64 TEB address>\n"
        L"  65488b042530000000 -- mov rax,qword ptr gs:[30h]\n");
  }
  return 0;
}
