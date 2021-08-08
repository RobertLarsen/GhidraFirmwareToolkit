package firmware.fs;

import java.util.Calendar;

public class Regular extends File {
    private long size;

    public Regular(Directory parent, String name, FileMode mode, String user, String group, Calendar modified, long size) {
        super(parent, name, mode, user, group, modified);
        this.size = size;
    }

    public long getSize() {
        return size;
    }
}
