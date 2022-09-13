package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.StructField;

import java.util.List;
import java.util.ArrayList;

public class ByteArray_StructField extends StructField<List<Byte>> {
    public ByteArray_StructField(BytesView view, String name, int length) {
        super(view, "byte[]", name, length);
    }

    protected List<Byte> read(BytesView view, int index) {
        this.value = new ArrayList<>(getSize());
        for (int i = 0; i < getSize(); i++) {
            this.value.add(view.getByteAt(index + i));
        }
        return this.value;
    }

    protected void write(BytesView view, int index, List<Byte> value) {
        this.value = value;
        for (int i = 0; i < value.size(); i++) {
            view.setByteAt(value.get(i), index + i);
        }
    }

    public byte[] simple() {
        List<Byte> value = getValue();
        byte res[] = new byte[value.size()];
        for (int i = 0; i < res.length; i++) {
            res[i] = value.get(i).byteValue();
        }
        return res;
    }

    public void simple(byte[] value) {
        List<Byte> lst = new ArrayList<>(value.length);
        for (int i = 0; i < value.length; i++) {
            lst.add(Byte.valueOf(value[i]));
        }
        write(lst);
    }
}
