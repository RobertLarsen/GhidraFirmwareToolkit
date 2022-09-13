package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.Elf_Dyn;

public class Elf64_Dyn extends StructImpl implements Elf_Dyn {
    public Elf64_Dyn(BytesView view) {
        super(
                view,
                new UInt64_StructField(view, "d_tag"),
                new UInt64_StructField(view, "d_val")
        );
    }

    public long d_tag() {
        return this.<UInt64_StructField>get("d_tag").simple();
    }

    public void d_tag(long value) {
        this.<UInt64_StructField>get("d_tag").simple(value);
    }

    public long d_val() {
        return this.<UInt64_StructField>get("d_val").simple();
    }

    public void d_val(long value) {
        this.<UInt64_StructField>get("d_val").simple(value);
    }
}
