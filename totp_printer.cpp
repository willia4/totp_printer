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

#include <vector>
#include <format>
#include "utils.h"
#include "crypto.h"
#include <ctime>
#include <map>
#include <optional>
#include <algorithm>
#include <cppcodec/base32_default_rfc4648.hpp>
#include <shlwapi.h>

struct TOTPConfig {
    std::string secret;
    crypto::E_HASH_ALGORITHM hashAlgorithm;
    int digits;
    int period;
    bool copyToClipboard;
    bool writeToStdOut;
};

std::wstring GetMainExePath() {
    TCHAR module[MAX_PATH];

    SetLastError(0);
    const auto setCount = GetModuleFileName(nullptr, module, MAX_PATH);

    const auto lastError = GetLastError();
    if (setCount <= 0) {
        throw std::runtime_error(std::format("Could not get module name; GetModuleFileName returned {}", setCount));
    }

    if (lastError != 0) {
        throw std::runtime_error(std::format("Could not get module name; GetModuleFileName set error {}", lastError));
    }

    module[MAX_PATH - 1] = 0;
    return std::wstring(module);
}

std::wstring GetMainExeFileName() {
    const auto modulePath = GetMainExePath();

    TCHAR modulePath_c[MAX_PATH];
    wcsncpy_s<MAX_PATH>(modulePath_c, modulePath.c_str(), modulePath.size());
    PathStripPath(modulePath_c);
    return std::wstring(modulePath_c);
}

// the version number is in the version resource stored in totp_printer.rc and can be updated via the resource editor
std::wstring GetVersionNumber() {
    const auto modulePath = GetMainExePath();

	DWORD dummy = 0;
    const DWORD fileVersionInfoDataSize = GetFileVersionInfoSize(modulePath.c_str(), &dummy);
    if (fileVersionInfoDataSize <= 0) {
        throw std::runtime_error(std::format("Could not get file version size info; Error code: ", GetLastError()));
    }

    std::vector<BYTE> fileVersionInfoData(fileVersionInfoDataSize);
    if (!GetFileVersionInfo(modulePath.c_str(), dummy, fileVersionInfoDataSize, fileVersionInfoData.data())) {
        throw std::runtime_error(std::format("Could not get file version info; Error code: ", GetLastError()));
    }

    VS_FIXEDFILEINFO  *versionData = nullptr;
    unsigned int versionDataSize = 0;
    if (!VerQueryValue(fileVersionInfoData.data(), L"\\", (LPVOID*)&versionData, &versionDataSize)) {
        return std::wstring(L"0.0.0.0");
    }

    const auto major = HIWORD(versionData->dwFileVersionMS);
    const auto minor = LOWORD(versionData->dwFileVersionMS);
    const auto patch = HIWORD(versionData->dwFileVersionLS);
    const auto rev = LOWORD(versionData->dwFileVersionLS);

    return std::format(L"{}.{}.{}.{}", major, minor, patch, rev);
}

void PrintUsage() {
    const auto fileName = GetMainExeFileName();
    const auto version = GetVersionNumber();
    const auto firstLine = std::format(L"  {} --secret <shared secret> [--digits <num digits>]", fileName);
    const auto indentCount = firstLine.find(L"-", 0);
    const auto indent = std::wstring(indentCount, L' ');

    WriteStringn(firstLine);
    WriteStringn(std::format(L"  {}[--period <period>] [--hash <hash algorithm>]", indent));
    WriteStringn(std::format(L"  {}[--copy] [--no-out] [--help] [--version]", indent));

    WriteStringn("");
    WriteStringn("  Print a Time-Based One-Time password to the console");
    WriteStringn(std::format(L"  Version: {}", version));
    WriteStringn("");
    WriteStringn("");
    //             "01234567890123456789012345678901234567890123456789012345678901234567890123456789"
    WriteStringn(L"     --secret    REQUIRED          ");
    WriteStringn(L"                 the shared secret for the password,          ");
    WriteStringn(L"                 encoded in base32.                           ");
    WriteStringn(L"                 available as the \"secret\" parameter        ");
    WriteStringn(L"                 of the otpauth URL or QR code                ");
    WriteStringn(L"                                                              ");
    WriteStringn(L"     --digits    OPTIONAL <Default: 6>");
    WriteStringn(L"                 the number of digits for the password.       ");
    WriteStringn(L"                 available as the \"digits\" parameter        ");
    WriteStringn(L"                 of the otpauth URL or QR code                ");
    WriteStringn(L"                                                              ");
    WriteStringn(L"     --period    OPTIONAL <Default: 30>");
    WriteStringn(L"                 the period for which a password is valid,    ");
    WriteStringn(L"                 in seconds.                                  ");
    WriteStringn(L"                 available as the \"digits\" parameter        ");
    WriteStringn(L"                 of the otpauth URL or QR code                ");
    WriteStringn(L"                                                              ");
    WriteStringn(L"     --hash      OPTIONAL <Default: sha1>");
    WriteStringn(L"                 the hashing algorithm for the password,      ");
    WriteStringn(L"                 must be one of sha1, sha256, sha512.         ");
    WriteStringn(L"                 available as the \"algorithm \" parameter    ");
    WriteStringn(L"                 of the otpauth URL or QR code                ");
    WriteStringn(L"                                                              ");
    WriteStringn(L"     --copy      OPTIONAL FLAG                                ");
    WriteStringn(L"                 copies the password to the Windows           ");
    WriteStringn(L"                 clipboard in addition to outputting it       ");
    WriteStringn(L"                                                              ");
    WriteStringn(L"     --no-out    OPTIONAL FLAG                                ");
    WriteStringn(L"                 Do not write the password the console output ");
    WriteStringn(L"                                                              ");
    WriteStringn(L"     --help      OPTIONAL FLAG                                ");
    WriteStringn(L"                 prints this message and exits                ");
    WriteStringn(L"");
    WriteStringn(L"     --version   OPTIONAL FLAG                                ");
    WriteStringn(L"                 prints the program's version and exits       ");
    WriteStringn(L"");
    WriteStringn("  Examples: ");
    WriteStringn(std::format(L"  {} --secret JBSWY3DPEHPK3PXP", fileName));
    WriteStringn("");
    WriteStringn(std::format(L"  {} --secret JBSWY3DPEHPK3PXP --hash sha256", fileName));
    WriteStringn("");
    WriteStringn(std::format(L"  {} --secret JBSWY3DPEHPK3PXP --hash sha1 --period 30 --digits 6", fileName));
    WriteStringn("");
    WriteStringn("");
    WriteStringn("  More information: https://github.com/willia4/totp_printer");
    WriteStringn("");
}

TOTPConfig ParseCommandLine(const int argc, char* argv[]) {
    if (argc <= 1) {
        WriteStringn(std::format("Required argument is missing: {}", "--secret"));
        WriteStringn("");
        PrintUsage();
        ExitProcess(2);
    }
    
    std::vector < std::string > args{};
    std::transform(argv + 1, argv + argc,std::back_inserter(args), [](const char* p) { return std::string(p); });

    std::map<std::string, std::optional<std::string>> parsedArgs;
    parsedArgs["--secret"] = std::nullopt;
    parsedArgs["--period"] = std::optional<std::string>("30");
    parsedArgs["--algorithm"] = std::optional<std::string>("sha1");
    parsedArgs["--digits"] = std::optional<std::string>("6");

    std::map<std::string, bool> flags;
    flags["--copy"] = false;
    flags["--no-out"] = false;
    flags["--help"] = false;
    flags["--version"] = false;

    for (size_t i = 0; i < args.size(); i++) {
        const auto &first = args[i];

        if (parsedArgs.contains(first)) {
            if (i + 1 >= args.size()) {
                WriteStringn(std::format("Argument {} requires an option", first));
                WriteStringn("");
                PrintUsage();
                ExitProcess(1);
            }

            i++;
            parsedArgs[first] = args[i];
        }
        else if (flags.contains(first)) {
            flags[first] = true;
        }
        else {
            WriteStringn(std::format( "Unexpected argument: {}", first));
            WriteStringn("");
            PrintUsage();
            ExitProcess(1);
        }
    }

    if (flags["--help"]) {
        PrintUsage();
        ExitProcess(0);
    }

    if (flags["--version"]) {
        WriteStringn(std::format(L"Version: {}", GetVersionNumber()));
        ExitProcess(0);
    }

    for (auto [fst, snd] : parsedArgs) {
        if (!snd.has_value()) {
            WriteStringn(std::format("Required argument is missing: {}", fst));
            WriteStringn("");
            PrintUsage();
            ExitProcess(2);
        }
    }

    const auto hashValue = parsedArgs["--algorithm"].value_or("");
    crypto::E_HASH_ALGORITHM hashAlgorithm = crypto::E_HASH_ALGORITHM::E_SHA1;
    if (hashValue == "sha1") {
        hashAlgorithm = crypto::E_HASH_ALGORITHM::E_SHA1;
    }
    else if (hashValue == "sha256") {
        hashAlgorithm = crypto::E_HASH_ALGORITHM::E_SHA256;
    }
    else if (hashValue == "sha512") {
        hashAlgorithm = crypto::E_HASH_ALGORITHM::E_SHA512;
    }
    else {
        WriteStringn(std::format("Invalid algorithm: {}", hashValue));
        WriteStringn("");
        PrintUsage();
        ExitProcess(2);
    }

    TOTPConfig res {};
    res.secret = parsedArgs["--secret"].value_or("");
    res.hashAlgorithm = hashAlgorithm;
    res.digits = std::stoi(parsedArgs["--digits"].value_or("6"));
    res.period = std::stoi(parsedArgs["--period"].value_or("30"));
    res.copyToClipboard = flags["--copy"];
    res.writeToStdOut = !flags["--no-out"];

    if (res.period <= 0) {
        throw std::runtime_error("--period must be greater than 0");
    }

    if (res.digits <= 0) {
        throw std::runtime_error("--digits must be greater than 0");
    }

    if (res.digits > 10) {
        throw std::runtime_error("--digits must be less than or equal to 10");
    }
    return res;
}

void SetTextToClipboard(const std::string text) {
    if (!OpenClipboard(nullptr)) {
        throw std::runtime_error("Could not open clipboard");
    }

    EmptyClipboard();

    const auto bufferSize = sizeof(char) * (text.size() + 1);
    const HGLOBAL dataHandle = GlobalAlloc(GMEM_MOVEABLE, bufferSize);
    if (dataHandle == nullptr) {
        throw std::runtime_error("Could not allocate clipboard data");
    }

    const auto dataDest = (char*) GlobalLock(dataHandle);
    strncpy_s(dataDest, bufferSize, text.c_str(), text.size() + 1);
    GlobalUnlock(dataHandle);

    const auto resultHandle = SetClipboardData(CF_TEXT, dataHandle);
    if (resultHandle == nullptr) {
	    // we only free the copy if the system didn't take ownership of it
        GlobalFree(dataHandle);
        throw std::runtime_error("Could not copy data to clipboard");
    }

    if (!CloseClipboard()) {
        throw std::runtime_error(std::format("Could not close clipboard: {}", GetLastError()));
    }
}
int main(const int argc, char *argv[])
{
    try {
        const auto parsed = ParseCommandLine(argc, argv);
        const auto sha1 = crypto::GetHashAlgorithm(parsed.hashAlgorithm);

        const auto time = (uint64_t)std::time(nullptr);

        const auto counter = IntToByteVector(time / parsed.period);
        const auto key = base32::decode(parsed.secret);
        const auto hotp = crypto::GenerateHOTP(sha1, counter, key, parsed.digits);

        const auto formatString = std::format("{{:0{}}}", parsed.digits);
        const auto formattedString = std::vformat(formatString, std::make_format_args(hotp));

        if (parsed.copyToClipboard) {
            SetTextToClipboard(formattedString);
        }

        if (parsed.writeToStdOut) {
            WriteString(formattedString);
        }
        
        return 0;
    }
    catch (const std::exception& e) {
        WriteString(std::format("Error: {}", e.what()));
        return -1;
    }
    catch (...) {
        WriteString("Unknown error");
        return -2;
    }
}
