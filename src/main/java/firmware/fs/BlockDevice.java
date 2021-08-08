package firmware.fs;

import java.util.Calendar;

public class BlockDevice extends Device {
    public BlockDevice(Directory parent, String name, FileMode mode, String user, String group, Calendar modified, int major, int minor) {
        super(parent, name, mode, user, group, modified, major, minor);
    }
}
