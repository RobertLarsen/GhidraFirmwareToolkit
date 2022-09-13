package firmware.elf;

public abstract class StructField<T> {
    private String type;
    private String name;
    private int size;
    private BytesView view;
    private int lastReadIndex;
    protected T value;

    public StructField(BytesView view, String type, String name, int size) {
        this.type = type;
        this.view = view;
        this.name = name;
        this.size = size;
        this.lastReadIndex = -1;
    }

    public String getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public int getSize() {
        return size;
    }

    public T getValue() {
        return value;
    }

    public T read(int index) {
        this.lastReadIndex = index;
        return read(view, index);
    }

    public void write(T value) {
        write(view, lastReadIndex, value);
    }

    public String extractInterface() {
        StringBuilder sb = new StringBuilder();
        sb.append("    ").append("public ").append(getType()).append(" ").append(getName()).append("();\n");
        sb.append("    ").append("public void ").append(getName()).append("(").append(getType()).append(" value);\n");
        return sb.toString();
    }

    public String extractImplementation() {
        StringBuilder sb = new StringBuilder();
        sb.append("    ").append("public ").append(getType()).append(" ").append(getName()).append("() {\n")
          .append("        return this.<").append(getClass().getSimpleName()).append(">get(\"").append(getName()).append("\").simple();\n")
          .append("    }\n\n");

        sb.append("    ").append("public void ").append(getName()).append("(").append(getType()).append(" value) {\n")
          .append("        this.<").append(getClass().getSimpleName()).append(">get(\"").append(getName()).append("\").simple(value);\n")
          .append("    }\n");

        return sb.toString();
    }

    protected abstract T read(BytesView view, int index);
    protected abstract void write(BytesView view, int index, T value);
}
