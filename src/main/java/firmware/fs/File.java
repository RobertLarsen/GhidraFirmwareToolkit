package firmware.fs;

import java.util.Calendar;

public abstract class File {
    private Directory parent;
    private String name;
    private FileMode mode;
    private String user;
    private String group;
    private Calendar modified;

    public File(Directory parent, String name, FileMode mode, String user, String group, Calendar modified) {
        this.parent   = parent;
        this.name     = name;
        this.mode     = mode;
        this.user     = user;
        this.group    = group;
        this.modified = modified;

        if (parent != null) {
            parent.add(this);
        }
    }

    public String getName() {
        return name;
    }

    public Directory getParent() {
        return parent;
    }

    public FileMode getMode() {
        return mode;
    }

    public String getUser() {
        return user;
    }

    public String getGroup() {
        return group;
    }

    public Calendar getModified() {
        return modified;
    }

    public String getAbsolutePath() {
        return parent == null ? name : parent.getAbsolutePath() + "/" + name;
    }

    public String toString() {
        return getAbsolutePath();
    }
}
