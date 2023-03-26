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

#include <cassert>
#include <cmath>
#include "crypto.h"

auto GetCryptoPropertyLength(const BCRYPT_HANDLE object, const wchar_t* propertyName) {
    ULONG cbValue;
    const auto status = BCryptGetProperty(object, propertyName, nullptr, 0, &cbValue, 0);

    THROW_NT_FAILURE(status, "Could not get property size");

    return cbValue;
}

std::tuple<ULONG, std::shared_ptr<unsigned char>> crypto::GetCryptoPropertyBytes(const BCRYPT_HANDLE object, const wchar_t* propertyName) {
    auto byteCount = GetCryptoPropertyLength(object, propertyName);
    
    const std::shared_ptr<unsigned char> bytes (new unsigned char[byteCount]);

    const auto status = BCryptGetProperty(object, propertyName, bytes.get(), byteCount, &byteCount, 0);
    THROW_NT_FAILURE(status, "Could not get property value");

    auto res = std::make_tuple(byteCount, bytes);
    return res;
}

LPCWSTR ConvertHashAlgorithmEnum(const crypto::E_HASH_ALGORITHM algorithm) {
    switch (algorithm) {
    case crypto::E_HASH_ALGORITHM::E_SHA1:
        return BCRYPT_SHA1_ALGORITHM;
    case crypto::E_HASH_ALGORITHM::E_SHA256:
        return BCRYPT_SHA256_ALGORITHM;
    case crypto::E_HASH_ALGORITHM::E_SHA512:
        return BCRYPT_SHA512_ALGORITHM;
    }
    
    throw std::runtime_error("Unexpected algorithm");
}

UniqueWrapper<BCRYPT_ALG_HANDLE> crypto::GetHashAlgorithm(const E_HASH_ALGORITHM algorithm) {

    BCRYPT_ALG_HANDLE ptr = nullptr;
    const LPCWSTR algorithmId = ConvertHashAlgorithmEnum(algorithm);

    const auto status = BCryptOpenAlgorithmProvider(&ptr, algorithmId, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    THROW_NT_FAILURE(status, "Could not open provider");

    if (ptr == nullptr) {
        throw std::runtime_error("Crypto provider pointer was unexpectedly null");
    }

    UniqueWrapper<BCRYPT_ALG_HANDLE> res(ptr, [](const BCRYPT_ALG_HANDLE p) {
        BCryptCloseAlgorithmProvider(p, 0);
        });

    return res;
}

int crypto::GetCryptoPropertyInt(const BCRYPT_HANDLE object, const wchar_t* propertyName) {
    const auto byteResult = GetCryptoPropertyBytes(object, propertyName);

    const auto byteCount = std::get<0>(byteResult);
    const auto bytes = std::get<1>(byteResult);
    const auto bytesPtr = bytes.get();

    assert(byteCount == 4);
    const auto i = reinterpret_cast<int*>(bytesPtr);
    return *i;
}

std::vector<unsigned char> crypto::HashData(BCRYPT_ALG_HANDLE algorithm, std::vector<unsigned char>data, std::vector<unsigned char> key) {
    const auto hashObjectSize = GetCryptoPropertyInt(algorithm, BCRYPT_OBJECT_LENGTH);
    auto hashObject = SafeHeapAlloc(hashObjectSize);

    const auto hashLength = GetCryptoPropertyInt(algorithm, BCRYPT_HASH_LENGTH);

    BCRYPT_HASH_HANDLE hasherHandle;
    const auto createStatus = BCryptCreateHash(algorithm, &hasherHandle, hashObject.get(), hashObjectSize, key.data(), key.size(), 0);
    THROW_NT_FAILURE(createStatus, "Could not create hasher");

    const auto hasher = UniqueWrapper<BCRYPT_HASH_HANDLE>(hasherHandle, [](BCRYPT_HASH_HANDLE h) { BCryptDestroyHash(h); });

    const auto hashStatus = BCryptHashData(hasher, data.data(), data.size(), 0);
    THROW_NT_FAILURE(hashStatus, "Could not hash data");

    auto hash = SafeHeapAlloc(hashLength);
    const auto finishStatus = BCryptFinishHash(hasher, hash, hashLength, 0);
    THROW_NT_FAILURE(finishStatus, "Could not finish hash");

    std::vector<unsigned char> hashBytes (hash.get(), hash.get() + hashLength);

    return hashBytes;
}

int DynamicTruncation(const std::vector<unsigned char> value) {
    const auto offset = value[value.size() - 1] & 0x0f; // lower 4 bits of the last byte
    const int p =
        ((int) value[offset] & 0x7f) << 24
        | ((int) value[offset + 1]) << 16
        | ((int) value[offset + 2]) << 8
        | ((int) value[offset + 3]);

    return p;
}

int crypto::GenerateHOTP(const BCRYPT_ALG_HANDLE algorithm, const std::vector<unsigned char> counter, const std::vector<unsigned char> key, const int digits) {
    const auto hmac = HashData(algorithm, counter, key);

    const auto truncate = DynamicTruncation(hmac);

    const auto mod = (int) pow(10, digits);
    return (int) (truncate % mod);
}