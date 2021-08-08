package firmware.fs;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;

public class Directory extends File implements Iterable<File> {
    private long size;
    private HashMap<String, File> content;

    public Directory(Directory parent, String name, FileMode mode, String user, String group, Calendar modified, long size) {
        super(parent, name, mode, user, group, modified);
        this.size = size;
        this.content = new HashMap<>();
    }

    public Directory(String name, FileMode mode, String user, String group, Calendar modified, long size) {
        this(null, name, mode, user, group, modified, size);
    }

    public Iterator<File> iterator() {
        return content.values().iterator();
    }

    public long getSize() {
        return size;
    }

    public void add(File file) {
        this.content.put(file.getName(), file);
    }

    public File get(String name) {
        return content.get(name);
    }
}
