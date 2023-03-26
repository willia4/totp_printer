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
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <windows.h>
#include <bcrypt.h>
#include "utils.h"

namespace crypto {
    enum class E_HASH_ALGORITHM {
        E_SHA1,
        E_SHA256,
        E_SHA512
    };

    int GetCryptoIntProperty(const BCRYPT_HANDLE object, const wchar_t* propertyName);

    UniqueWrapper<BCRYPT_ALG_HANDLE> GetHashAlgorithm(E_HASH_ALGORITHM algorithm);
    std::vector<unsigned char> HashData(BCRYPT_ALG_HANDLE algorithm, std::vector<unsigned char>data, std::vector<unsigned char> key);

    std::tuple<ULONG, std::shared_ptr<unsigned char>> GetCryptoPropertyBytes(const BCRYPT_HANDLE object, const wchar_t* propertyName);

    int GetCryptoPropertyInt(const BCRYPT_HANDLE object, const wchar_t* propertyName);

    int GenerateHOTP(const BCRYPT_ALG_HANDLE algorithm, const std::vector<unsigned char> counter, const std::vector<unsigned char>key, const int digits);
}
