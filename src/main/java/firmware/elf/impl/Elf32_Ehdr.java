package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.Elf_Ehdr;
import firmware.elf.Elf_Phdr;
import firmware.elf.Elf_Dyn;

public class Elf32_Ehdr extends Elf_EhdrImpl {
    public Elf32_Ehdr(BytesView view) {
        super(
                view,
                new ByteArray_StructField(view, "e_ident", 16),
                new UInt16_StructField(view, "e_type"),
                new UInt16_StructField(view, "e_machine"),
                new UInt32_StructField(view, "e_version"),
                new UInt32_StructField(view, "e_entry"),
                new UInt32_StructField(view, "e_phoff"),
                new UInt32_StructField(view, "e_shoff"),
                new UInt32_StructField(view, "e_flags"),
                new UInt16_StructField(view, "e_ehsize"),
                new UInt16_StructField(view, "e_phentsize"),
                new UInt16_StructField(view, "e_phnum"),
                new UInt16_StructField(view, "e_shentsize"),
                new UInt16_StructField(view, "e_shnum"),
                new UInt16_StructField(view, "e_shstrndx")
        );
    }

    public byte[] e_ident() {
        return this.<ByteArray_StructField>get("e_ident").simple();
    }

    public void e_ident(byte[] value) {
        this.<ByteArray_StructField>get("e_ident").simple(value);
    }

    public int e_type() {
        return this.<UInt16_StructField>get("e_type").simple();
    }

    public void e_type(int value) {
        this.<UInt16_StructField>get("e_type").simple(value);
    }

    public int e_machine() {
        return this.<UInt16_StructField>get("e_machine").simple();
    }

    public void e_machine(int value) {
        this.<UInt16_StructField>get("e_machine").simple(value);
    }

    public long e_version() {
        return this.<UInt32_StructField>get("e_version").simple();
    }

    public void e_version(long value) {
        this.<UInt32_StructField>get("e_version").simple(value);
    }

    public long e_entry() {
        return this.<UInt32_StructField>get("e_entry").simple();
    }

    public void e_entry(long value) {
        this.<UInt32_StructField>get("e_entry").simple(value);
    }

    public long e_phoff() {
        return this.<UInt32_StructField>get("e_phoff").simple();
    }

    public void e_phoff(long value) {
        this.<UInt32_StructField>get("e_phoff").simple(value);
    }

    public long e_shoff() {
        return this.<UInt32_StructField>get("e_shoff").simple();
    }

    public void e_shoff(long value) {
        this.<UInt32_StructField>get("e_shoff").simple(value);
    }

    public long e_flags() {
        return this.<UInt32_StructField>get("e_flags").simple();
    }

    public void e_flags(long value) {
        this.<UInt32_StructField>get("e_flags").simple(value);
    }

    public int e_ehsize() {
        return this.<UInt16_StructField>get("e_ehsize").simple();
    }

    public void e_ehsize(int value) {
        this.<UInt16_StructField>get("e_ehsize").simple(value);
    }

    public int e_phentsize() {
        return this.<UInt16_StructField>get("e_phentsize").simple();
    }

    public void e_phentsize(int value) {
        this.<UInt16_StructField>get("e_phentsize").simple(value);
    }

    public int e_phnum() {
        return this.<UInt16_StructField>get("e_phnum").simple();
    }

    public void e_phnum(int value) {
        this.<UInt16_StructField>get("e_phnum").simple(value);
    }

    public int e_shentsize() {
        return this.<UInt16_StructField>get("e_shentsize").simple();
    }

    public void e_shentsize(int value) {
        this.<UInt16_StructField>get("e_shentsize").simple(value);
    }

    public int e_shnum() {
        return this.<UInt16_StructField>get("e_shnum").simple();
    }

    public void e_shnum(int value) {
        this.<UInt16_StructField>get("e_shnum").simple(value);
    }

    public int e_shstrndx() {
        return this.<UInt16_StructField>get("e_shstrndx").simple();
    }

    public void e_shstrndx(int value) {
        this.<UInt16_StructField>get("e_shstrndx").simple(value);
    }

    protected Elf_Phdr createPhdr(BytesView view) {
        return new Elf32_Phdr(view);
    }

    protected Elf_Dyn createDyn(BytesView view) {
        return new Elf32_Dyn(view);
    }
}
