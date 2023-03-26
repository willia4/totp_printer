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

#include "utils.h"

std::unique_ptr<wchar_t[]> ConvertUtf8ToWChar(const char* s) {
    if (s == nullptr) {
        std::unique_ptr<wchar_t[]> empty(new wchar_t[1]);
        empty.get()[0] = 0;
        return empty;
    }

    const int sSize = (int)strlen(s) + 1;
    const auto neededSize = MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, s, sSize, nullptr, 0);

    if (neededSize <= 0) {
        const auto err = GetLastError();
        throw std::runtime_error("Could not convert string");
    }

    std::unique_ptr<wchar_t[]> res(new wchar_t[neededSize]);
    const auto r = MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, s, sSize, res.get(), neededSize);
    return res;
}

void WriteString(const wchar_t* s) {
    if (s == nullptr) {
        return;
    }

    const auto stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(stdoutHandle, s, (DWORD)wcslen(s) * 2, &written, nullptr);
}
