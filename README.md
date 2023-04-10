# MemoryMirror

## What is this?
This tool allows you to grab a running process and dump its memory such that it can (mostly) immediately be imported
into Ghidra for analysis.

## How do I use this?
- Start the process that you want to dump
- Start this tool
- Select the procress you want to dump in the tool
- Select an output directory for the dump to be written to by clicking "Select output directory"
- Click "Dump process memory"

After this is done it will have written your the memory regions that it was able to acquire to disk. It will write
the PE header and the actual executable sections to different files so they will need a manual concat.

## How does it work?
When you hit "Dump process memory", it enumerates all process threads, freezes them, dumps all memory regions that the
process has access to that are not in a `MEM_FREE` state.
If there's is a PE header in the memory region it corrects the `PointerToRawData` and `RawDataSize` fields in the
section headers such that Ghidra can use them to locate the sections again.

## Why would I ever want to have a runtime-dumped memory image in Ghidra?
Having the .data section filled-in and having the heap data in the repo can be very useful if you're looking to reverse
big, complex, structures.

## How to use this for MAX DUMPING CAPABILITIES?
There are a few things you can do to improve both your dumps and your analysis.

### Turn off ASLR on the program you're dumping
It makes communicating pointers just so much easier and there's usually way less math required than dealing with 
the virtual addresses that come with heap dumps.

### Order matters
In my experience it works best to do the dump, import just the memory image of your software and once that's done you
import the heap data. This is to prevent Ghidra from taking ages on the analysis but I also feel like running an
analysis on the heap causes Ghidra to goof on the analysis here and there.