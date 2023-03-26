/**
 *  Copyright (C) 2023 James Williams
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

#pragma once
#include <memory>
#include <stdexcept>
#include <windows.h>
#include <string>
#include "unique_wrapper.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef NT_FAILURE
#define NT_FAILURE(Status) ((NTSTATUS)(Status) < 0)
#endif

#ifndef THROW_NT_FAILURE
#define THROW_NT_FAILURE(Status, Msg) do { \
    if (NT_FAILURE(Status)) { \
		throw std::runtime_error(Msg); \
    }} while(false)
#endif

const auto STDOUT_HANDLE = GetStdHandle(STD_OUTPUT_HANDLE);

std::unique_ptr<wchar_t[]> ConvertUtf8ToWChar(const char* s);

void WriteString(const wchar_t* s);

inline void WriteString(const char* s) {
    if (s == nullptr) {
        return;
    }

    const auto wide = ConvertUtf8ToWChar(s);
    WriteString(wide.get());
}

inline void WriteString(const std::string& s) {
    WriteString(s.c_str());
}

inline void WriteString(const std::wstring& s) {
    WriteString(s.c_str());
}

inline void WriteStringn(const char *s) {
    WriteString(s);
    WriteString(L"\n");
}

inline void WriteStringn(const std::wstring &s) {
    WriteString(s);
    WriteString(L"\n");
}

inline void WriteStringn(const std::string& s) {
    WriteString(s.c_str());
    WriteString(L"\n");
}

inline void WriteStrinen(const std::wstring& s) {
    WriteString(s.c_str());
    WriteString(L"\n");
}

inline UniqueWrapper<PBYTE> SafeHeapAlloc(size_t size) {
    const auto bytes = HeapAlloc(GetProcessHeap(), 0, size);
    if (bytes == nullptr) {
        throw std::runtime_error("Could not allocate from heap");
    }

    return UniqueWrapper<PBYTE>((PBYTE)bytes, [](PBYTE p) { HeapFree(GetProcessHeap(), 0, p); });
}

inline std::vector<unsigned char> StringToByteVector(const char *s) {
    return std::vector<unsigned char> (s, s + strlen(s));
}

inline std::vector<unsigned char> StringToByteVector(const std::string& s) {
    return StringToByteVector(s.c_str());
}

inline std::vector<unsigned char> IntToByteVector(const uint64_t i) {
    return std::vector<unsigned char> {
			(unsigned char)((i & 0xff00000000000000) >> 56),
            (unsigned char)((i & 0x00ff000000000000) >> 48),
    		(unsigned char)((i & 0x0000ff0000000000) >> 40),
    		(unsigned char)((i & 0x000000ff00000000) >> 32),
            (unsigned char)((i & 0x00000000ff000000) >> 24),
            (unsigned char)((i & 0x0000000000ff0000) >> 16),
            (unsigned char)((i & 0x000000000000ff00) >>  8),
            (unsigned char)((i & 0x00000000000000ff) >>  0),
    };
}

inline std::vector<unsigned char> IntToByteVector(const int i) {
    return std::vector<unsigned char> {
        (unsigned char) ((i & 0xff000000 ) >> 24),
    	(unsigned char) ((i & 0x00ff0000 ) >> 16),
    	(unsigned char) ((i & 0x0000ff00) >>  8),
    	(unsigned char) ((i & 0x000000ff) >>  0)
    };
}