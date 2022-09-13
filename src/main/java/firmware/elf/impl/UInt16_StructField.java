package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.StructField;

public class UInt16_StructField extends StructField<Integer> {
    public UInt16_StructField(BytesView view, String name) {
        super(view, "int", name, 2);
    }

    protected Integer read(BytesView view, int index) {
        return (this.value = Integer.valueOf(view.getUnsignedShortAt(index)));
    }

    protected void write(BytesView view, int index, Integer value) {
        view.setUnsignedShortAt((this.value = value).intValue(), index);
    }

    public int simple() {
        return getValue().intValue();
    }

    public void simple(int value) {
        write(Integer.valueOf(value));
    }
}
