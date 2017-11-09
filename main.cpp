#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <atlbase.h>
#include <dia2.h>
#include <string>
#include <algorithm>
#include <functional>
#include <sstream>

#define Log wprintf

void LogDebug(LPCWSTR format, ...) {
  WCHAR linebuf[1024];
  va_list v;
  va_start(v, format);
  StringCbVPrintf(linebuf, sizeof(linebuf), format, v);
  OutputDebugString(linebuf);
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
  } *dos_;

  HMODULE imagebase_;
  const IMAGE_SECTION_HEADER *code_;

  void Release() {
    if (imagebase_) {
      FreeLibrary(imagebase_);
      imagebase_ = nullptr;
      code_ = nullptr;
    }
  }

public:
  PE() : imagebase_(nullptr), code_(nullptr) {}

  ~PE() {
    Release();
  }

  template<typename T>
  const T *As(DWORD offset) const {
    return reinterpret_cast<T*>(reinterpret_cast<const PBYTE>(imagebase_) + offset);
  }

  bool Load(LPCWSTR filename) {
    imagebase_ = LoadLibrary(filename);
    if (!imagebase_) {
      Log(L"LoadLibrary failed - %08x", GetLastError());
      return false;
    }

    DWORD offset = 0;
    auto dos = As<DOS_Header>(offset);
    offset += dos->e_lfanew;
    offset += 4; // PE signature

    auto header = As<IMAGE_FILE_HEADER>(offset);
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

    for (int i = 0; i < header->NumberOfSections; ++i) {
      auto section = As<IMAGE_SECTION_HEADER>(offset);
      /*
      Log(L"Section#%02d %-8hs %08x\n",
          i + 1,
          reinterpret_cast<LPCSTR>(section->Name),
          section->VirtualAddress);
      */
      const BYTE dot_text[] = {0x2e, 0x74, 0x65, 0x78, 0x74};
      if (memcmp(section->Name, dot_text, sizeof(dot_text)) == 0) {
        code_ = section;
        break;
      }
      offset += sizeof(IMAGE_SECTION_HEADER);
    }
    return true;
  }

  void Search(const std::string &needle,
              std::function<void(DWORD)> callback) {
    if (!code_) return;

    Log(L"Start searching...\n");

    auto section_start = As<BYTE>(code_->VirtualAddress);
    auto section_end = As<BYTE>(code_->VirtualAddress + code_->SizeOfRawData);
    auto needle_start = reinterpret_cast<const unsigned char*>(needle.data());
    auto needle_end = needle_start + needle.size();
    auto it = std::search(section_start,
                          section_end,
                          needle_start,
                          needle_end);
    while (it != section_end) {
      DWORD rva = static_cast<DWORD>(it - As<BYTE>(0));
      //Log(L"+%08x %02x %02x\n", rva, *it, *(it + 1));
      callback(rva);
      it = std::search(it + needle.size(),
                       section_end,
                       needle_start,
                       needle_end);
    }
  }
};

class DIACallbacks : public IDiaLoadCallback2 {
private:
  LONG ref_;
public:
  DIACallbacks() : ref_(1) {}

  // IUnknown

  STDMETHODIMP QueryInterface(REFIID riid,
                              _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppv) {
    static QITAB rgqit[] = {
      QITABENT(DIACallbacks, IDiaLoadCallback),
      QITABENT(DIACallbacks, IDiaLoadCallback2),
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
    return E_NOTIMPL;
  }

  STDMETHODIMP NotifyOpenDBG(LPCOLESTR dbgPath,
                             HRESULT resultCode) {
    return E_NOTIMPL;
  }

  STDMETHODIMP NotifyOpenPDB(LPCOLESTR pdbPath,
                             HRESULT resultCode) {
    return E_NOTIMPL;
  }

  STDMETHODIMP RestrictRegistryAccess() {
    return E_NOTIMPL;
  }

  STDMETHODIMP RestrictSymbolServerAccess() {
    return E_NOTIMPL;
  }

  // IDiaLoadCallback2

  STDMETHODIMP RestrictOriginalPathAccess() {
    return E_NOTIMPL;
  }

  STDMETHODIMP RestrictReferencePathAccess() {
    return E_NOTIMPL;
  }

  STDMETHODIMP RestrictDBGAccess() {
    return E_NOTIMPL;
  }

  STDMETHODIMP RestrictSystemRootAccess() {
    return E_NOTIMPL;
  }
};

void EnumSymbols(LPCWSTR exepath,
                 LPCWSTR symbol_path,
                 const std::string &pattern) {
  PE pe;
  if (pe.Load(exepath)) {
    CComPtr<IDiaSession> session;

    if (symbol_path) {
      CComPtr<IDiaDataSource> dia;
      HRESULT hr = dia.CoCreateInstance(CLSID_DiaSource,
                                        nullptr,
                                        CLSCTX_INPROC_SERVER);
      if (SUCCEEDED(hr)) {
        DIACallbacks callbacks;
        hr = dia->loadDataForExe(exepath, symbol_path, &callbacks);
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
        Log(L"+%08x\t%s +%x\n", rva, symbol_name, displacement);
      }
      else {
        Log(L"+%08x\n", rva);
      }
    });

  }
}

int wmain(int argc, wchar_t *argv[]) {
  if (argc >= 3) {
    if (SUCCEEDED(CoInitialize(nullptr))) {
      bstream<std::wstring> bs;
      bs << argv[2];
      auto s = bs.get();
      EnumSymbols(argv[1],
                  argc >= 4 ? argv[3] : nullptr,
                  s);
      CoUninitialize();
    }
  }
  else {
    Log(L"USAGE: PESCAN <PE> <pattern> [Symbol location]\n\n"
        L"Pattern examples:\n\n"
        L"  <Stack Pivot>\n"
        L"  94:c3 -- xchg eax,esp\n"
        L"           ret\n\n"
        L"  <Get x64 TEB address>\n"
        L"  65488b042530000000 -- mov rax,qword ptr gs:[30h]\n");
  }
  return 0;
}
