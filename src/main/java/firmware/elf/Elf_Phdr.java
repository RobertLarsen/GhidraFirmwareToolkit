package firmware.elf;

public interface Elf_Phdr extends Struct {
    public long p_type();
    public void p_type(long value);
    public long p_flags();
    public void p_flags(long value);
    public long p_offset();
    public void p_offset(long value);
    public long p_vaddr();
    public void p_vaddr(long value);
    public long p_paddr();
    public void p_paddr(long value);
    public long p_filesz();
    public void p_filesz(long value);
    public long p_memsz();
    public void p_memsz(long value);
    public long p_align();
    public void p_align(long value);
}
