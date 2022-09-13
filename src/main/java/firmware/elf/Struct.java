package firmware.elf;

public interface Struct {
    public String extractInterface();
    public String extractImplementation();
    public int getSize();
    public int read(int index);
    public <T extends StructField> T get(String name);
}
