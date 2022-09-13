package firmware.elf;

public interface Elf_Ehdr extends Struct {
    public byte[] e_ident();
    public void e_ident(byte[] value);
    public int e_type();
    public void e_type(int value);
    public int e_machine();
    public void e_machine(int value);
    public long e_version();
    public void e_version(long value);
    public long e_entry();
    public void e_entry(long value);
    public long e_phoff();
    public void e_phoff(long value);
    public long e_shoff();
    public void e_shoff(long value);
    public long e_flags();
    public void e_flags(long value);
    public int e_ehsize();
    public void e_ehsize(int value);
    public int e_phentsize();
    public void e_phentsize(int value);
    public int e_phnum();
    public void e_phnum(int value);
    public int e_shentsize();
    public void e_shentsize(int value);
    public int e_shnum();
    public void e_shnum(int value);
    public int e_shstrndx();
    public void e_shstrndx(int value);

    public Elf_Phdr[] getPhdrs();
	public Elf_Dyn[] getDynamic();
}
