#add a heap util for display heap information,such as display fastbin,unsortedbin and other bins

>usage:
>1.display all heap arenas information

```bash
gdb-peda$ heap_arenas
```

>2.display main_arena information

```bash
gdb-peda$ heap
Arena (base=0xb7fb5780,top chunk=0x804b020,last_remainder=0x0,next=0xb7fb5780,next_free=0x0,system_mem=0x21000)
```

>3.display a heap chunk information according to the specified address

```bash
gdb-peda$ heap_chunk 0x0804b008
Chunk (used): 0x804b000
Chunk size: 16 (0x10)
Usable size: 12 (0xc)
No Previous chunk
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

>4.display all bins information (0-127)

```bash
gdb-peda$ heap_bins
```

>5.display unsortedbins information

```bash
gdb-peda$ heap_bins_unsorted
```

>6.display fastbin information

```bash
gdb-peda$ heap_bins_fast
```

>7.display small bins information

```bash
gdb-peda$ heap_bins_small
```

>8.display large bins information

```bash
gdb-peda$ heap_bins_large
```

>need modify(judge not fully)

```python
arch = gdb.selected_frame().architecture()
arch_name = arch.name()
if "64" in arch_name:
    self.__arch = 8#64
else:
    self.__arch = 4#32
```
