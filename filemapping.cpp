#include <windows.h>
#include <algorithm>
#include "filemapping.h"

void Log(LPCWSTR format, ...);

FileMapping::View FileMapping::View::CreateView(HANDLE sectionObject,
                                                DWORD desiredAccess,
                                                DWORD offset,
                                                SIZE_T sizeToMap) {
  auto p = MapViewOfFile(sectionObject,
                         desiredAccess,
                         /*dwFileOffsetHigh*/0,
                         offset,
                         sizeToMap);
  if (!p) {
    Log(L"MapViewOfFile failed - %08x\n", GetLastError());
  }
  return View(p);
}

FileMapping::View::View() : bits_(nullptr)
{}

FileMapping::View::View(LPVOID p) : bits_(p)
{}

FileMapping::View::View(View &&other) : bits_(nullptr) {
  std::swap(bits_, other.bits_);
}

FileMapping::View::~View() {
  if (bits_ && !UnmapViewOfFile(bits_)) {
    Log(L"UnmapViewOfFile failed - %08x\n", GetLastError());
  }
}

FileMapping::View &FileMapping::View::operator=(FileMapping::View &&other) {
  if (this != &other) {
    std::swap(bits_, other.bits_);
  }
  return *this;
}

FileMapping::View::operator LPBYTE() {
  return reinterpret_cast<LPBYTE>(bits_);
}

FileMapping::View::operator LPCBYTE() const {
  return reinterpret_cast<LPCBYTE>(bits_);
}

void FileMapping::Release() {
  if (section_ != INVALID_HANDLE_VALUE) {
    CloseHandle(section_);
  }
}

FileMapping::FileMapping() : section_(nullptr)
{}

FileMapping::~FileMapping() {
  Release();
}

FileMapping::FileMapping(FileMapping &&other) : section_(nullptr) {
  std::swap(section_, other.section_);
}

FileMapping &FileMapping::operator=(FileMapping &&other) {
  if (this != &other) {
    Release();
    std::swap(section_, other.section_);
  }
  return *this;
}

FileMapping::operator HANDLE() {
  return section_;
}

FileMapping::operator HANDLE() const {
  return section_;
}

HANDLE FileMapping::Attach(HANDLE sectionObject) {
  Release();
  return section_ = sectionObject;
}

FileMapping::View FileMapping::CreateMappedView(DWORD desiredAccess,
                                                DWORD offset,
                                                SIZE_T sizeToMap) const {
  return View::CreateView(section_, desiredAccess, offset, sizeToMap);
}

bool FileMapping::Create(LPCWSTR filename,
                         LPCWSTR sectionName,
                         ULARGE_INTEGER mappingAreaSize,
                         DWORD desiredAccess,
                         DWORD mappingProtection) {
  Release();

  HANDLE mappedFile = INVALID_HANDLE_VALUE;
  if (filename) {
    mappedFile = CreateFile(filename,
                            desiredAccess,
                            FILE_SHARE_READ,
                            /*lpSecurityAttributes*/nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            /*hTemplateFile*/nullptr);
    if (mappedFile == INVALID_HANDLE_VALUE) {
      Log(L"CreateFile failed - %08x\n", GetLastError());
      goto cleanup;
    }
  }

  section_ = CreateFileMapping(mappedFile,
                               /*lpFileMappingAttributes*/nullptr,
                               mappingProtection,
                               mappingAreaSize.HighPart,
                               mappingAreaSize.LowPart,
                               sectionName);
  if (!section_) {
    Log(L"CreateFileMapping failed - %08x\n", GetLastError());
    goto cleanup;
  }

cleanup:
  if (mappedFile != INVALID_HANDLE_VALUE) {
    CloseHandle(mappedFile);
  }
  return !!section_;
}

bool FileMapping::Open(LPCWSTR sectionName, DWORD desiredAccess) {
  Release();
  section_ = OpenFileMapping(desiredAccess,
                             /*bInheritHandle*/FALSE,
                             sectionName);
  if (!section_) {
    Log(L"OpenFileMapping failed - %08x\n", GetLastError());
  }
  return !!section_;
}
