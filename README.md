## richie_rich

A portable command-line tool for browsing, stripping, and verifying the Rich header, found in Windows executables that were built with Microsoft's toolchain.

## Building

Tested on Linux, MacOS, and Windows with [MSYS2+MinGW64](https://www.msys2.org/).

In most cases you simply need to do this:

`[ab@gibson]$ mkdir build && make`

Building with debugging logs:

```bash
[ab@gibson]$ mkdir build
[ab@gibson]$ make debug=true
```

Cross-compiling on UNIX-based systems with mingw (make sure to edit the `MINGWCC` in the `Makefile` accordingly):

```
mkdir build
make cc-win=true
```
## Usage

```bash
[ab@gibson]$ ./richie_rich
Usage: ./richie_rich -i path_to_pe [-w out_file] [-o rich_header_offset] [-v] [-s]

  -i    Path to the subject PE (required)
  -s    Strip the rich header from the executable (requires -w)
  -w    Path to the new PE file
  -o    Set a custom rich header offset (default is 128)
  -v    Verify the Rich header checksum

```
The `-o` parameter is useful in the rare cases when the DOS header has a non-standard DOS stub.
When omitted, the default offset of `0x80` is used, which will be good for most cases.

By default, the Rich header will be decoded, parsed, and presented as a table:

```bash
[ab@gibson]$ ./richie_rich -i vs_compiled_me.exe
------------------------------------------------------
Count    Minor Version    ProdID
------------------------------------------------------
11       27412            Utc1900_C (0x0104)
5        27412            Masm1400 (0x0103)
137      27412            Utc1900_CPP (0x0105)
3        27412            Implib1400 (0x0101)
89       0                Import0 (0x0001)
37       30034            Utc1900_CPP (0x0105)
16       30034            Utc1900_C (0x0104)
9        30034            Masm1400 (0x0103)
1        30038            Utc1900_C (0x0104)
1        30038            Linker1400 (0x0102)
```

The `-v` option will verify the checksum in the Rich header, for example:

```bash
[ab@gibson]$ ./richie_rich -i bad_rich_header.exe -v
------------------------------------------------------
Count    Minor Version    ProdID
------------------------------------------------------
                ...

[info] The Rich header checksum is invalid
[info] Checksum in the header:  0x00870d47
[info] Real checksum:           0x35c3913a

```

The `-s` option allows you to strip the Rich header from the subject
executable. Note that the original file will never be altered. Instead, you
should provide a new file name through the `-w` parameter:

```bash
[ab@gibson]$ ./richie_rich -i strip_me.exe -s -w stripped.exe -v
------------------------------------------------------
Count    Minor Version    ProdID
------------------------------------------------------
3        30034            Implib1400 (0x0101)
23       30034            Utc1900_CPP (0x0105)
11       30034            Utc1900_C (0x0104)
3        30034            Masm1400 (0x0103)
4        27412            Implib1400 (0x0101)
70       0                Import0 (0x0001)
1        30038            Utc1900_CPP (0x0105)
1        30038            Cvtres1400 (0x00ff)
1        30038            Linker1400 (0x0102)

[info] The Rich header checksum is valid
[info] Stripping the Rich header (output in "stripped.exe")
```

Read `prodid.h` if you're wondering where I got the ProdID values.

## Upcoming Features

- Ability to add/replace existing Rich header with a realistic fake Rich
  header.

## About the Rich header

There's already a ton of info out there about this undocumented PE structure. I strongly recommend reading this paper:

```
Webster, George & Kolosnjaji, Bojan & Pentz, Christian & Kirsch, Julian & Hanif, Zachary & Zarras, Apostolis & Eckert, Claudia. (2017). Finding the Needle: A Study of the PE32 Rich Header and Respective Malware Triage. 119-138. 10.1007/978-3-319-60876-1_6.
```
