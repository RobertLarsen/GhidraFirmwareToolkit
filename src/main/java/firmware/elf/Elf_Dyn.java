package firmware.elf;

public interface Elf_Dyn extends Struct {
    public final static int DT_NULL = 0;
    public final static int DT_NEEDED = 1;
    public final static int DT_PLTRELSZ = 2;
    public final static int DT_PLTGOT = 3;
    public final static int DT_HASH = 4;
    public final static int DT_STRTAB = 5;
    public final static int DT_SYMTAB = 6;
    public final static int DT_RELA = 7;
    public final static int DT_RELASZ = 8;
    public final static int DT_RELAENT = 9;
    public final static int DT_STRSZ = 10;
    public final static int DT_SYMENT = 11;
    public final static int DT_INIT = 12;
    public final static int DT_FINI = 13;
    public final static int DT_SONAME = 14;
    public final static int DT_RPATH = 15;
    public final static int DT_SYMBOLIC = 16;
    public final static int DT_REL = 17;
    public final static int DT_RELSZ = 18;
    public final static int DT_RELENT = 19;
    public final static int DT_PLTREL = 20;
    public final static int DT_DEBUG = 21;
    public final static int DT_TEXTREL = 22;
    public final static int DT_JMPREL = 23;
    public final static int DT_BIND_NOW = 24;
    public final static int DT_INIT_ARRAY = 25;
    public final static int DT_FINI_ARRAY = 26;
    public final static int DT_INIT_ARRAYSZ = 27;
    public final static int DT_FINI_ARRAYSZ = 28;
    public final static int DT_RUNPATH = 29;
    public final static int DT_FLAGS = 30;
    public final static int DT_ENCODING = 32;
    public final static int DT_PREINIT_ARRAY = 32;
    public final static int DT_PREINIT_ARRAYSZ = 33;
    public final static int DT_SYMTAB_SHNDX = 34;
    public final static int DT_GNU_HASH = 0x6ffffef5;
    public final static int DT_VERNEED = 0x6ffffffe;
    public final static int DT_VERNEEDNUM = 0x6fffffff;
    public final static int DT_VERSYM = 0x6ffffff0;
    public final static int DT_RELACOUNT = 0x6ffffff9;
    public final static int DT_RELCOUNT = 0x6ffffffa;
    public final static int DT_FLAGS_1 = 0x6ffffffb;

    public long d_tag();
    public void d_tag(long value);
    public long d_val();
    public void d_val(long value);
}
