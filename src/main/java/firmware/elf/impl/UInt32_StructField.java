package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.StructField;

public class UInt32_StructField extends StructField<Long> {
    public UInt32_StructField(BytesView view, String name) {
        super(view, "long", name, 4);
    }

    protected Long read(BytesView view, int index) {
        return (this.value = Long.valueOf(view.getUnsignedIntAt(index)));
    }

    protected void write(BytesView view, int index, Long value) {
        view.setUnsignedIntAt((this.value = value).longValue(), index);
    }

    public long simple() {
        return getValue().longValue();
    }

    public void simple(long value) {
        write(Long.valueOf(value));
    }
}
