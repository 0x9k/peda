# -*-coding:utf-8-*-
__author__ = 'joker'

import sys
import struct
import gdb
sys.path.append('../')

"""
define constants、color and some functions for heap utils
定义一些heap工具需要使用到的常量和颜色 颜色来自peda自带的color
"""
from utils import message,colorize
#display
right_arrow = "->"#for show

#tool function
def get_target_endian_str():
    """
        得到端模式
    :return:
    """
    endian = gdb.execute("show endian", to_string=True)
    if "little endian" in endian:
        return "<" # LE
    elif "big endian" in endian:
        return ">" # BE
    else:
        raise gdb.GdbError("unknown endianness '{0}'".format(str(endian)))

def read_memory(addr,length=0x10):
    """
        读取指定位置的内存
    :param addr:
    :param length:
    :return:
    """
    return gdb.selected_inferior().read_memory(addr, length).tobytes()#py3
    #gdb.selected_inferior().read_memory(addr, length) py2

def read_int_from_memory(addr,arch=4):#arch与体系结构相关
    mem = read_memory(addr,arch)
    fmt = get_target_endian_str()+"I" if arch==4 else get_target_endian_str()+"Q"
    return struct.unpack(fmt, mem)[0]
#tool function


"""
define data structure for heap,such as struct malloc_state定义和heap相关的数据结构
"""
#c data structure
class GlibcArena:
    """
    Glibc arena class
    Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1671
    struct malloc_state
    {

          mutex_t mutex;/* Serialize access.  */

          int flags;/* Flags (formerly in max_fast).  */

          mfastbinptr fastbinsY[NFASTBINS]; /* Fastbins */

          mchunkptr top;/* Base of the topmost chunk -- not otherwise kept in a bin */

          mchunkptr last_remainder;/* The remainder from the most recent split of a small request */

          mchunkptr bins[NBINS * 2 - 2];/* Normal bins packed as described above */

          unsigned int binmap[BINMAPSIZE]; /* Bitmap of bins */

          struct malloc_state *next;/* Linked list */

          struct malloc_state *next_free; /* Linked list for free arenas.  Access to this field is serialized by free_list_lock in arena.c.  */

          INTERNAL_SIZE_T attached_threads;/* Number of threads attached to this arena.0 if the arena is on the free list.Access to this field is serialized by free_list_lock in arena.c.  */
          INTERNAL_SIZE_T system_mem;  /* Memory allocated from the system in this arena.  */
          INTERNAL_SIZE_T max_system_mem;
    };"""


    def __init__(self, addr=None):
        arch = gdb.selected_frame().architecture()
        arch_name = arch.name()
        if "64" in arch_name:#可能判断还不够充分 后续要需要修改
            self.__arch = 8#64
        else:
            self.__arch = 4#32
        arena = gdb.parse_and_eval(addr)
        self.__arena = arena.cast(gdb.lookup_type("struct malloc_state")).reference_value()
        self.__main_arena_addr = self.__arena.address
        self.__top = self.__arena['top']
        self.__last_remainder = self.__arena['last_remainder']
        self.__next = self.__arena['next']
        self.__next_free = self.__arena['next_free']
        self.__system_mem = self.__arena['system_mem']
        self.__bins = self.__arena['bins']
        self.__fastbinsY = self.__arena['fastbinsY']
        return

    def get_arch(self):
        """
            architecture
        :return:
        """
        return self.__arch

    def get_main_arena_addr(self):
        """
            return __main_arena_addr
        :return:
        """
        return int(self.__main_arena_addr)

    def get_bins_len(self):
        """
            return __bins
        :return:
        """
        return len(self.__bins)

    def fastbin(self,i):
        """
            get the number i of fastbin  fastbin in array[]
            取得第i个fastbin
        :param i:
        :return:
        """
        fastbin_i_addr = int(self.__fastbinsY[i])
        if fastbin_i_addr == 0x00:
            return None
        else:
            return GlibcChunk(fastbin_i_addr + 2*self.__arch)

    def bin(self,i):
        """
            get the number i of bin
        :param i:
        :return:
        """
        idx = i*2#双向
        fd = int(self.__bins[idx])#fd指针
        bw = int(self.__bins[idx+1])#bk指针
        return (fd, bw)

    def __getitem__(self, item):
        """
            use like GlibcArena['top']
        :param item:
        :return:
        """
        return self.__arena[item]#GlibcArena['top']

    def __getattr__(self, item):
        """
            use like GlibcArena['last_remainder']
        :param item:
        :return:
        """
        return self.__arena[item]#GlibcArena['last_remainder']

    def __str__(self):
        """
            printable
        :return:
        """
        _base_addr = self.__main_arena_addr
        _top = self.__top
        _last_remainder = self.__last_remainder
        _next = self.__next
        _next_free = self.__next_free
        _system_mem = self.__system_mem
        m = "Arena ("
        m+= "base={0},".format(hex(int(_base_addr)))
        m+= "top chunk={0},".format(hex(int(_top)))
        m+= "last_remainder={0},".format(hex(int(_last_remainder)))
        m+= "next={0},".format(hex(int(_next)))
        m+= "next_free={0},".format(hex(int(_next_free)))
        m+= "system_mem={0}".format(hex(int(_system_mem)))
        m+= ")"
        return m

    def get_next(self):
        """
            get next arena
        :return:
        """
        addr_next = int(self.__next)
        arena_main = GlibcArena("main_arena")
        if addr_next == arena_main.__main_arena_addr:
            return None
        addr_next = "*0x%x " % addr_next
        return GlibcArena(addr_next)


class GlibcChunk:
    """
    Glibc chunk class. chunk信息
    Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
    struct malloc_chunk {
      INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
      INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

      struct malloc_chunk* fd;         /* double links -- used only if free. */
      struct malloc_chunk* bk;

      /* Only used for large blocks: pointer to next larger size.  */
      struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
      struct malloc_chunk* bk_nextsize;
    };


    allocated chunk
       chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Size of previous chunk, if allocated            | |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Size of chunk, in bytes                       |M|P|
          mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             User data starts here...                          .
          .                                                               .
          .             (malloc_usable_size() bytes)                      .
          .                                                               |
    nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Size of chunk                                     |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Free chunks
      chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Size of previous chunk                            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        `head:' |             Size of chunk, in bytes                         |P|
          mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Forward pointer to next chunk in list             |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Back pointer to previous chunk in list            |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |             Unused space (may be 0 bytes long)                .
          .                                                               .
          .                                                               |
    nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        `foot:' |             Size of chunk, in bytes                           |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, addr, from_base_flag=False):
        """
             from_base_flag是否丛chunk最开始地址开始 默认是从malloc返回给用户的地址开始
        :param addr:
        :param from_base_flag:
        """
        arch = gdb.selected_frame().architecture()
        arch_name = arch.name()
        if "64" in arch_name:#判断还不够充分 还需修改
            self.arch = 8#64
        else:
            self.arch = 4#32
        if from_base_flag:
            self.chunk_start_addr = addr#包含pre_size和size
            self.chunk_data_addr = addr + 2*self.arch#返回给用户的起始地址
        else:
            self.chunk_start_addr = addr - 2*self.arch#chunk起始地址 丛prev_size开始 -2*4(32) -2*8(64)
            self.chunk_data_addr = addr

        self.chunk_size_addr  = self.chunk_start_addr + self.arch#chunk size地址
        self.chunk_prev_size_addr = self.chunk_start_addr#前一块chunk地址
        return


    def get_chunk_size(self):
        """
            get chunk size
            取得chunk的大小 去掉最低标志位
        :param self:
        :return:
        """
        return read_int_from_memory(self.chunk_size_addr)&(~0x03)


    def get_usable_size(self):
        """
            https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L4537
            返回chunk大小  表示返回给用户
            #include <stdio.h>
            #include <stdlib.h>
            #include <malloc.h>

            int main()
            {
                char *a = (char *)malloc(100);
                printf("%d\n",malloc_usable_size(a));
                return 0;
            }
            返回100
            0x804b000:	0x00000000	0x00000069
            实际用户可用的空间0x60
            http://www.man7.org/linux/man-pages/man3/malloc_usable_size.3.html
        :param self:
        :return:
        """

        chunk_size = self.get_chunk_size()
        if chunk_size == 0x00:
            return chunk_size
        if self.has_M_bit():
            return chunk_size - 2*self.arch#mmap
        return chunk_size - self.arch#

    def get_prev_chunk_size(self):
        """
            P为0则表示前一个chunk为空闲,这时chunk的第一个域prev_size才有效,prev_size表示前一个chunk的size
        :return:
        """
        if self.has_P_bit() == 0:
            return read_int_from_memory(self.chunk_prev_size_addr)
        else:
            return -1


    def get_next_chunk(self):
        """
             得到下一个chunk
        :param self:
        :return:
        """

        addr = self.chunk_data_addr + self.get_chunk_size()
        return GlibcChunk(addr)

    #if free-ed functions
    def get_fwd_ptr(self):
        """
            得到fd指针 只有空闲chunk才存在 M状态不存在只有NP状态 fd指向后一个空闲的chunk 而bk指向前一个空闲的chunk
        :param self:
        :return:
        """
        return read_int_from_memory(self.chunk_data_addr)  # fd

    def get_bkw_ptr(self):
        """
            得到fd指针 只有空闲chunk才存在 M状态不存在只有NP状态 fd指向后一个空闲的chunk 而bk指向前一个空闲的chunk
        :param self:
        :return:
        """
        return read_int_from_memory(self.chunk_data_addr + self.arch)#bk
    #endif free-ed functions


    def has_P_bit(self):
        """
            Check for in PREV_INUSE bit
            Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1267
        :param self:
        :return:
        """
        return read_int_from_memory(self.chunk_size_addr) & 0x01

    def has_M_bit(self):
        """
            Check for in IS_MMAPPED bit
            Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1274
            M,他表示当前chunk是从哪个内存区域获得的虚拟内存。M为1表示该chunk是从mmap映射区域分配的,否则是从heap区域分配
        :param self:
        :return:
        """
        return read_int_from_memory(self.chunk_size_addr) & 0x02

    def has_N_bit(self):
        """
            Check for in NON_MAIN_ARENA bit.
            Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1283
            :param self:
            :return:
        """
        return read_int_from_memory(self.chunk_size_addr) & 0x04

    def is_used(self):
        """
            Check if the current block is used by:
            - checking the M bit is true
            - or checking that next chunk PREV_INUSE flag is true
            当前chunk是否已经被使用,需要看它的下一个chunk的P位是不是为1 或者如果该chunk直接是mmap分配M位为1也是占用状态
            M他表示当前chunk是从哪个内存区域获得的虚拟内存。M为1表示该chunk是从mmap映射区域分配的
        :param self:
        :return:
        """

        if self.has_M_bit():#mmap分配
            return True

        next_chunk = self.get_next_chunk()

        if next_chunk.has_P_bit():#下一块的P位是不是1 表示本chunk是否被使用
            return True
        else:
            return False


    def str_chunk_size_flag(self):
        """
            chunk flag information
        :param self:
        :return:
        """

        msg = ""
        msg+= "PREV_INUSE flag: "
        msg+= "On" if self.has_P_bit() else "Off"
        msg+= "\n"

        msg+= "IS_MMAPPED flag: "
        msg+= "On" if self.has_M_bit() else "Off"
        msg+= "\n"

        msg+= "NON_MAIN_ARENA flag: "
        msg+= "On" if self.has_N_bit() else "Off"

        return msg


    def _str_sizes(self):
        """
            chunk size information
        :param self:
        :return:
        """

        msg = ""
        failed = False

        try:
            msg+= "Chunk size: {0:d} ({0:#x})\n".format(self.get_chunk_size())
            msg+= "Usable size: {0:d} ({0:#x})\n".format(self.get_usable_size())
            failed = True
        except gdb.MemoryError as me:
            msg+= "Chunk size: Cannot read at {0:#x} (corrupted?)\n".format(self.chunk_size_addr)

        try:
            prev_chunk_size = self.get_prev_chunk_size()
            if prev_chunk_size == -1:
                msg+= "No Previous chunk\n"
            else:
                msg+= "Previous chunk size: {0:d} ({0:#x})\n".format(self.get_prev_chunk_size())
            failed = True
        except gdb.MemoryError as me:
            msg+= "Previous chunk size: Cannot read at {0:#x} (corrupted?)\n".format(self.chunk_start_addr)

        if failed:
            msg+= self.str_chunk_size_flag()

        return msg

    def _str_pointers(self):
        """
            fd and bk pointer
        :param self:
        :return:
        """

        fwd = self.chunk_data_addr#fd指针
        bkw = self.chunk_data_addr + self.arch#bk指针

        msg = ""

        try:
            fwd_ptr = self.get_fwd_ptr()
            if fwd_ptr == -1:
                msg+= "Forward pointer: None\n"
            else:
                msg+= "Forward pointer: {0:#x}\n".format(fwd_ptr)
        except gdb.MemoryError as me:
            msg+= "Forward pointer: {0:#x} (corrupted?)\n".format(fwd)

        try:
            bkw_ptr = self.get_bkw_ptr()
            if bkw_ptr == -1:
                msg+= "Backward pointer: None\n"
            else:
                msg+= "Backward pointer: {0:#x}\n".format(bkw_ptr)
        except gdb.MemoryError as me:
            msg+= "Backward pointer: {0:#x} (corrupted?)\n".format(bkw)

        return msg

    def str_as_alloced(self):
        """

        :param self:
        :return:
        """

        return self._str_sizes()

    def str_as_freeed(self):
        return self._str_sizes() + '\n'*2 + self._str_pointers()

    def __str__(self):
        """
            printable
        :param self:
        :return:
        """

        m = ""
        m+="FreeChunk" if not self.is_used() else "UsedChunk"
        m+= "(addr={:#x},size={:#x})".format(int(self.chunk_data_addr),self.get_chunk_size())
        return m

    def pprint(self):
        """

        :param self:
        :return:
        """

        msg = ""
        if not self.is_used():
            msg += "Chunk (free): %#x" % self.chunk_start_addr
            msg += "\n"
            msg += self.str_as_freeed()
        else:
            msg += "Chunk (used): %#x" % self.chunk_start_addr
            msg += "\n"
            msg += self.str_as_alloced()

        #gdb.write(msg+"\n")
        #gdb.flush()
        msg_print = message()
        msg_print(colorize("{0}".format(msg), "purple"))
        return
#c data structure



#gdb Command Base
class GlibcGenericCommand(gdb.Command):
    """
        base class for glibc
    """
    def invoke(self,args,from_tty):
        pass

    def usage(self):
        pass

#gdb python command
class GlibcHeapArenaCommand(GlibcGenericCommand):
    """Display information on a heap chunk. 显示heap中所有的arena相关信息 gdb接口 调用GlibcArena"""

    def __init__(self):
        _cmdline_ = "heap_arenas"#使用方式 价格usage函数
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)
        return

    def invoke(self,args,from_tty):
        if "--help" in args or "--h" in args:
            self.usage()
            return
        else:
            try:
                arena = GlibcArena("main_arena")
            except:
                self.msg(colorize("Error: Could not find Glibc main arena", "red"))
            while True:
                self.msg(colorize("%s" % (arena,), "purple"))
                arena = arena.get_next()
                if arena is None:
                    break
            return

    def usage(self):
        self.msg(colorize("Usage heap_arenas", "blue"))
        return


class GlibcHeapCommand(GlibcGenericCommand):
    """Base command to get information about the Glibc heap structure. 获取heap main_arena信息并显示 只显示main_arena"""

    def __init__(self):
        _cmdline_ = "heap"
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)

    def invoke(self, args,from_tty):
        if "--help" in args or "--h" in args:
            self.usage()
            return
        _arena = self.get_main_arena()
        self.msg(colorize("{0}".format(_arena), "blue"))
        return

    def usage(self):
        self.msg(colorize("Usage heap", "blue"))
        return

    def get_main_arena(self):
        try:
            arena = GlibcArena("main_arena")
        except:
            self.msg(colorize("Error: Could not find Glibc main arena", "red"))
        return arena



class GlibcHeapChunkCommand(GlibcGenericCommand):
    """Display information on a heap chunk.
        See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123 显示指定地址的heap chunk信息 地址可以是malloc返回 也可以就是heap chunk的起始地址"""

    def __init__(self):
        _cmdline_ = "heap_chunk"
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)
        return

    def invoke(self,args,from_tty):
        if args == "":
            self.usage()
            return
        addr = int(gdb.parse_and_eval(args))#python3中int代替long
        chunk = GlibcChunk(addr)
        chunk.pprint()
        return

    def usage(self):
        self.msg(colorize("Usage heap_chunk [malloced_location(addr is malloc return)]", "blue"))
        self.msg(colorize("eaxmple:heap_chunk 0x804b008", "blue"))


class GlibcHeapBinsCommand(GlibcGenericCommand):
    """Display information on the bins on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123 显示指定的bins信息 可以是fast_bins也可以是small unsorted large
    Ptmalloc一共维护了128个bin,并使用一个数组来存储这些bin
    数组中的第一个为unsorted bin,数组中从2开始编号的前64个bin称为small_bins,同一个small_bin中的chunk具有相同的大小
    """

    def __init__(self):
        _cmdline_ = "heap_bins"
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)
        return

    def invoke(self,args,from_tty):
        if "--help" in args or "--h" in args:
            self.usage()
            return

        self.msg(colorize("all bins:", "green"))
        for i in range(128):#128个bins
            GlibcHeapBinsCommand.pprint_bin(i)
        return

    def usage(self):
        self.msg(colorize("Usage heap_bins", "blue"))

    @staticmethod#静态
    def pprint_bin(bin_idx):
        msg = message()
        arena = GlibcArena("main_arena")
        fw, bk = arena.bin(bin_idx)
        msg(colorize("Found base for bin({:d}): fw={:#x}, bk={:#x}".format(bin_idx, fw, bk), "purple"))
        if bk == fw and ((arena.get_main_arena_addr()&~0xFFFF) == (bk&~0xFFFF)):
            #print("Empty")
            msg(colorize("Empty","purple"))
            return

        m = ""
        head = GlibcChunk(bk+2*arena.get_arch()).get_fwd_ptr()
        while fw != head:
            chunk = GlibcChunk(fw+2*arena.get_arch())
            m+= "{:s}  {:s}  ".format(right_arrow, str(chunk))
            fw = chunk.get_fwd_ptr()
        msg(colorize("{0}".format(m), "purple"))
        return

class GlibcHeapUnsortedBinsCommand(GlibcGenericCommand):
    """Display information on the Unsorted Bins of an arena (default: main_arena).
    See: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1689
    显示unsorted bins
    unsorted bin 是数组0
    """

    def __init__(self):
        _cmdline_ = "heap_bins_unsorted"
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)
        return

    def invoke(self, args,from_tty):
        if "--help" in args or "--h" in args:
            self.usage()
            return
        arena = GlibcArena("main_arena")
        arena_addr = arena.get_main_arena_addr()
        self.msg(colorize("Information on Unsorted Bin of arena '{0}'".format(hex(arena_addr)), "purple"))
        GlibcHeapBinsCommand.pprint_bin(0)
        return

    def usage(self):
        self.msg(colorize("Usage heap_bins_unsorted", "blue"))

class GlibcHeapFastbinsYCommand(GlibcGenericCommand):
    """Display information on the fastbinsY on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123
    https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1680
    fastbins
    """

    def __init__(self):
        _cmdline_ = "heap_bins_fast"
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)
        return


    def invoke(self, args,from_tty):
        if "--help" in args or "--h" in args:
            self.usage()
            return

        arena = GlibcArena("main_arena")
        fastbin_list = []#avoid ring
        flag_finish = False#avoid ring
        arena_addr = arena.get_main_arena_addr()
        self.msg(colorize("Information on FastBins of arena '{0}'".format(hex(arena_addr)), "white"))
        for i in range(10):
            m = "Fastbin[{:d}] ".format(i,)
            chunk = arena.fastbin(i)
            if chunk is None:#none other fastbins
                continue
            if chunk.chunk_data_addr not in fastbin_list:
                fastbin_list.append(chunk.chunk_data_addr)
            while True:
                if chunk is None:
                    m+= "0x00"
                    break
                try:
                    m+= "{0}  {1}  ".format(right_arrow, str(chunk))
                    if flag_finish == True:
                        break
                    next_chunk = chunk.get_fwd_ptr()#-1终止
                    if next_chunk == -1:
                        break
                    chunk = GlibcChunk(next_chunk,from_base_flag=True)
                    if chunk.chunk_data_addr in fastbin_list:
                        flag_finish = True
                    fastbin_list.append(chunk.chunk_data_addr)
                except gdb.MemoryError:
                    break
            self.msg(colorize("{0}".format(m), "purple"))
        return

    def usage(self):
        self.msg(colorize("heap_bins_fast", "blue"))
        return


class GlibcHeapSmallBinsCommand(GlibcGenericCommand):
    """Convience command for viewing small bins
    显示small bins 是数组 1-64
    """

    def __init__(self):
        _cmdline_ = "heap_bins_small"
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)
        return

    def invoke(self, args,from_tty):
        if "--help" in args or "--h" in args:
            self.usage()
        arena = GlibcArena("main_arena")
        arena_addr = arena.get_main_arena_addr()
        self.msg(colorize("Information on Small Bins of arena '{0}'".format(hex(arena_addr)), "purple"))
        for i in range(1,64):
            GlibcHeapBinsCommand.pprint_bin(i)
        return

    def usage(self):
        self.msg(colorize("heap_bins_small", "blue"))
        return

class GlibcHeapLargeBinsCommand(GlibcGenericCommand):
    """Convience command for viewing large bins
    large bins 是数组64-127
    """

    def __init__(self):
        _cmdline_ = "heap_bins_large"
        _syntax_ = "%s" % _cmdline_
        self.msg = message()

        super(self.__class__, self).__init__(_syntax_, gdb.COMMAND_USER)
        return


    def invoke(self, args,from_tty):
        if "--help" in args or "--h" in args:
            self.usage()
            return
        arena = GlibcArena("main_arena")
        arena_addr = arena.get_main_arena_addr()
        self.msg(colorize("Information on Large Bins of arena '{0}'".format(hex(arena_addr)),"purple"))
        for i in range(64,127):
            GlibcHeapBinsCommand.pprint_bin(i)
        return

    def usage(self):
        self.msg(colorize("heap_bins_large", "blue"))

#gdb python command
