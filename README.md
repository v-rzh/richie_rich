## richie_rich

A portable command-line tool for extracting the Rich header form PE files.

## Building

In most cases you simply need to run `make`. 
Tested on Linux, MacOS, and Windows with [MSYS2+MinGW64](https://www.msys2.org/).

Building with debugging logs:
```
make debug=true
```

Cross-compiling on UNIX-based systems with mingw (make sure to edit the `MINGWCC` in the `Makefile` accordingly):
```
make cc-win=true
```
## Usage
```bash
[ab@gibson]# ./richie_rich 
Usage: ./richie_rich <path_to_pe> [rich_header_offset]
```
The `rich_header_offset` parameter is useful in the rare cases when the DOS header has a non-standard DOS stub.
When omitted, the default offset of `0x80` is used, which will be good for most cases.
If present, the Rich header will be decoded, parsed, and presented as a table:

```bash
[ab@gibson]# ./richie_rich vs_compiled_me.exe
------------------------------------------------------
Count    Minor Version	ProdID
------------------------------------------------------
11       27412          Utc1900_C (0x0104)
5        27412          Masm1400 (0x0103)
137      27412          Utc1900_CPP (0x0105)
3        27412          Implib1400 (0x0101)
89       0              Import0 (0x0001)
37       30034          Utc1900_CPP (0x0105)
16       30034          Utc1900_C (0x0104)
9        30034          Masm1400 (0x0103)
1        30038          Utc1900_C (0x0104)
1        30038          Linker1400 (0x0102)
```

Read `prodid.h` if you're wondering where I got the ProdID values.

## About the Rich header

There's already a ton of info out there about this undocumented PE structure. I strongly recommend reading this paper:

```
Webster, George & Kolosnjaji, Bojan & Pentz, Christian & Kirsch, Julian & Hanif, Zachary & Zarras, Apostolis & Eckert, Claudia. (2017). Finding the Needle: A Study of the PE32 Rich Header and Respective Malware Triage. 119-138. 10.1007/978-3-319-60876-1_6. 
```
