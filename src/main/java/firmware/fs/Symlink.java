package firmware.fs;

import java.util.Calendar;

public class Symlink extends File {
    private String link;
    private Filesystem fs;

    public Symlink(Directory parent, String name, FileMode mode, String user, String group, Calendar modified, String link, Filesystem fs) {
        super(parent, name, mode, user, group, modified);
        this.link = link;
        this.fs = fs;
    }

    public String getLink() {
        return link;
    }

    public File resolve() {
        return fs.resolve(this);
    }

    public File resolveDeep() {
        return fs.resolveDeep(this);
    }
}
