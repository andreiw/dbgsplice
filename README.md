dbgsplice
=========

Merge COFF symbol table into stripped EXE.
 
This tool is a debugging aid meant to simplify disassembling
stripped Windows NT binaries. Checked builds of NT came with
DBG files (e.g. support/debug/ppc/symbols/exe/ntoskrnl.dbg for
ntoskrnl.exe), but normal tools (Microsoft's dumpbin,
OpenWatcom wdis) don't make use of DBG files and thus
yield a pretty useless disassembly.

Status
------

dbgsplice only takes care of the COFF symbol table today. This
is good enough for dumpbin. Tools that care about CV (Windbg...?)
know about symbol files after all.

- I didn't verify that the resulting image is good
  enough for running (i.e. checksum is not updated).
- Should be endian clean.
- And supports PE/COFF files with and without MZ headers.
- Architecture agnostic.
- Some sanity checking that DBG and EXE match.

Building
--------

    $ make dbgsplice

Using
-----

    $ dbgsplice ntkrnlmp.dbg  ntkrnlmp.exe ntkrnlmp-with-syms.exe
    Done!
    ...
    Q:\> dumpbin /DISASM ntkrnlmp-with-syms.exe > ntkrnlmp-with-syms.txt

![and we have syms](withsyms.png?raw=true "have syms")

Contact Info
------------

Andrei Warkentin (andrey.warkentin@gmail.com).
