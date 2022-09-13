package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.Elf_Dyn;

public class Elf32_Dyn extends StructImpl implements Elf_Dyn {
    public Elf32_Dyn(BytesView view) {
        super(
                view,
                new UInt32_StructField(view, "d_tag"),
                new UInt32_StructField(view, "d_val")
        );
    }

    public long d_tag() {
        return this.<UInt32_StructField>get("d_tag").simple();
    }

    public void d_tag(long value) {
        this.<UInt32_StructField>get("d_tag").simple(value);
    }

    public long d_val() {
        return this.<UInt32_StructField>get("d_val").simple();
    }

    public void d_val(long value) {
        this.<UInt32_StructField>get("d_val").simple(value);
    }
}
