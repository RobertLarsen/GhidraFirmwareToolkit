package firmware.fs;

import java.util.Calendar;

public class Device extends File {
    private int major;
    private int minor;

    public Device(Directory parent, String name, FileMode mode, String user, String group, Calendar modified, int major, int minor) {
        super(parent, name, mode, user, group, modified);
        this.major = major;
        this.minor = minor;
    }

    public int getMajor() {
        return major;
    }

    public int getMinor() {
        return minor;
    }
}
