package firmware.fs;

import java.util.Calendar;

public class CharDevice extends Device {
    public CharDevice(Directory parent, String name, FileMode mode, String user, String group, Calendar modified, int major, int minor) {
        super(parent, name, mode, user, group, modified, major, minor);
    }
}
