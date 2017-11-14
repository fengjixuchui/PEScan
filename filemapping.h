class FileMapping {
private:
  HANDLE section_;

  void Release();

public:
  class View {
  private:
    LPVOID bits_;

    View(LPVOID p);

  public:
    static View CreateView(HANDLE sectionObject,
                           DWORD desiredAccess,
                           DWORD offset,
                           SIZE_T sizeToMap);

    View();
    View(View &&other);
    ~View();
    View &operator=(View &&other);
    operator LPBYTE();
    operator LPCBYTE() const;
    template<class T> const T *As(DWORD offset) const {
      return reinterpret_cast<const T*>(reinterpret_cast<LPCBYTE>(bits_) + offset);
    }
  };

  FileMapping();
  FileMapping(FileMapping &&other);
  ~FileMapping();
  FileMapping &operator=(FileMapping &&other);
  operator HANDLE();
  operator HANDLE() const;
  HANDLE Attach(HANDLE sectionObject);
  View CreateMappedView(DWORD desiredAccess,
                        DWORD offset,
                        SIZE_T sizeToMap) const;
  bool Create(LPCWSTR filename,
              LPCWSTR sectionName,
              ULARGE_INTEGER mappingAreaSize,
              DWORD desiredAccess,
              DWORD mappingProtection);
  bool Open(LPCWSTR sectionName, DWORD desiredAccess);
};
