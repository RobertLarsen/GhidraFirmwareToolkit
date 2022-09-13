package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.StructField;

public class UInt64_StructField extends StructField<Long> {
    public UInt64_StructField(BytesView view, String name) {
        super(view, "long", name, 8);
    }

    protected Long read(BytesView view, int index) {
        return (this.value = Long.valueOf(view.getLongAt(index)));
    }

    protected void write(BytesView view, int index, Long value) {
        view.setLongAt((this.value = value).longValue(), index);
    }

    public long simple() {
        return getValue().longValue();
    }

    public void simple(long value) {
        write(Long.valueOf(value));
    }
}
