package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.Elf_Phdr;

public class Elf64_Phdr extends StructImpl implements Elf_Phdr {
	public Elf64_Phdr(BytesView view) {
		super(
				view,
				new UInt32_StructField(view, "p_type"),
				new UInt32_StructField(view, "p_flags"),
				new UInt64_StructField(view, "p_offset"),
				new UInt64_StructField(view, "p_vaddr"),
				new UInt64_StructField(view, "p_paddr"),
				new UInt64_StructField(view, "p_filesz"),
				new UInt64_StructField(view, "p_memsz"),
				new UInt64_StructField(view, "p_align")
			 );
	}

	public long p_type() {
		return this.<UInt32_StructField>get("p_type").simple();
	}

	public void p_type(long value) {
		this.<UInt32_StructField>get("p_type").simple(value);
	}

	public long p_flags() {
		return this.<UInt32_StructField>get("p_flags").simple();
	}

	public void p_flags(long value) {
		this.<UInt32_StructField>get("p_flags").simple(value);
	}

	public long p_offset() {
		return this.<UInt64_StructField>get("p_offset").simple();
	}

	public void p_offset(long value) {
		this.<UInt64_StructField>get("p_offset").simple(value);
	}

	public long p_vaddr() {
		return this.<UInt64_StructField>get("p_vaddr").simple();
	}

	public void p_vaddr(long value) {
		this.<UInt64_StructField>get("p_vaddr").simple(value);
	}

	public long p_paddr() {
		return this.<UInt64_StructField>get("p_paddr").simple();
	}

	public void p_paddr(long value) {
		this.<UInt64_StructField>get("p_paddr").simple(value);
	}

	public long p_filesz() {
		return this.<UInt64_StructField>get("p_filesz").simple();
	}

	public void p_filesz(long value) {
		this.<UInt64_StructField>get("p_filesz").simple(value);
	}

	public long p_memsz() {
		return this.<UInt64_StructField>get("p_memsz").simple();
	}

	public void p_memsz(long value) {
		this.<UInt64_StructField>get("p_memsz").simple(value);
	}

	public long p_align() {
		return this.<UInt64_StructField>get("p_align").simple();
	}

	public void p_align(long value) {
		this.<UInt64_StructField>get("p_align").simple(value);
	}
}
