# TOTP Printer

A Windows command line utility for printing Time-Based One-Time Passwords to stdout, configured by command line arguments.

## Why?

This program is, largely, ill-advised.

It is primarily targeted at keyboard macro utilities which can run commands and then replace typed text with the output of those commands.
This allows configuring keyboard macros that can quickly type one-time passwords.

You almost certainly shouldn't use this. It's a terrible idea. It probably means that you're storing your TOTP shared-secret in an unecrypted disk file somewhere.

That's terrible. Don't do it.

## Why C++?

In its intended use-case as part of a keyboard macro, speed is paramount. No one wants to wait on their keyboard.

Nicer languages like C# can have significant startup overhead.

Being under 300 kilobytes, it is _very_ fast to load this program into memory and start executing it.

C++ at least has the potential for memory safety with RAII patterns.

This was also an opportunity to learn a little C++ and Win32 programming. If you know what you are doing, you will quickly see that I know _very little_ of both.

One day, I may rewrite this terrible C++ program in terrible Rust instead.

## How do I use it?

Most TOTP sources provide a QR code to make it easier to bring into an app. This QR code will decode into [a URI with standard query parameters][otpauth_standard].

You will need the "secret" parameter. If provided, you may also use the "digits", "period", and "algorithm" parameters. These correspond to the `--secret`, `--digits`, `--period`, and `--algorithm` command line parameters of the program. Only `--secret` is required.

```
totp_printer.exe --secret JBSWY3DPEHPK3PXP
```

```
totp_printer.exe --secret JBSWY3DPEHPK3PXP --digits 10 --period 15 --algorithm sha256
```

Only the `sha1`, `sha256`, and `sha512` hash algorithms are currently supported.

[otpauth_standard]: https://github.com/google/google-authenticator/wiki/Key-Uri-Format

## How do I build it?

I don't know enough about the C++ ecosystem to provide proper build instructions.

I just used Visual Studio 2022.

## Who did this?

This is a misguided experiment from [James Williams](https://jameswilliams.me).

Because base32 is terrible (who wants to deal with 5-bit offsets?), the [cppcodec library](https://github.com/tplgy/cppcodec) from Topology Inc and Jakob Petsovits is used under the MIT license.

If you want to perpetuate a bad idea, the rest of this code is also licensed using the MIT license. See the LICENSE.txt file for details.
