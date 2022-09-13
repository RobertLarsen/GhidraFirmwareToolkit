package firmware.elf.impl;

import firmware.elf.BytesView;
import firmware.elf.Struct;
import firmware.elf.StructField;

public class StructImpl implements Struct {
    private BytesView view;
    private StructField fields[];

    public StructImpl(BytesView view, StructField ... fields) {
        this.view = view;
        this.fields = fields;
    }

    public BytesView getView() {
        return view;
    }

    public String extractInterface() {
        StringBuilder sb = new StringBuilder("public interface ").append(getClass().getSimpleName()).append(" {\n");
        for (StructField f : fields) {
            sb.append(f.extractInterface());
        }

        return sb.append("}").toString();
    }

    public String extractImplementation() {
        StringBuilder sb = new StringBuilder("public interface ").append(getClass().getSimpleName()).append(" {\n");
        for (StructField f : fields) {
            sb.append(f.extractImplementation()).append("\n");
        }

        return sb.append("}").toString();
    }

    public int getSize() {
        int s = 0;
        for (StructField f : fields) {
            s += f.getSize();
        }
        return s;
    }

    public int read(int index) {
        for (StructField f : fields) {
            f.read(index);
            index += f.getSize();
        }
        return index;
    }

    public <T extends StructField> T get(String name) {
        for (StructField f : fields) {
            if (f.getName().equals(name)) {
                return (T)f;
            }
        }
        return null;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(getClass().getSimpleName()).append(" {\n");
        for (int i = 0; i < fields.length; i++) {
            sb.append("    ").append(fields[i].getName()).append(": ").append(fields[i].getValue().toString()).append("\n");
        }
        sb.append("}");
        return sb.toString();
    }
}

