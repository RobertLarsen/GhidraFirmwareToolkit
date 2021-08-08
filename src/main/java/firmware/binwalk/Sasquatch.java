package firmware.binwalk;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Calendar;

import java.nio.file.Path;
import java.nio.file.Files;

import firmware.fs.*;

public class Sasquatch {
    private ExecutableWrapper sasquatch;

    public Sasquatch(File path) throws FileNotFoundException {
        sasquatch = new ExecutableWrapper(path);
    }

    public Sasquatch(String path) throws FileNotFoundException {
        this(new File(path));
    }

    public Sasquatch() throws FileNotFoundException {
        this("/usr/local/bin/sasquatch");
    }

    private Calendar parseCalendar(String date, String time) {
        String parts[] = date.split("-");
        int dateParts[] = new int[] { Integer.parseInt(parts[0]), Integer.parseInt(parts[1]), Integer.parseInt(parts[2]) };
        parts = time.split(":");
        int timeParts[] = new int[] { Integer.parseInt(parts[0]), Integer.parseInt(parts[1]) };

        Calendar res = Calendar.getInstance();
        res.set(dateParts[0], dateParts[1], dateParts[2], timeParts[0], timeParts[1], 0);
        return res;
    }

    private Directory addDirectory(Filesystem fs, Matcher m) {
        String perm = m.group(1);
        String owner = m.group(2);
        String group = m.group(3);
        String size = m.group(4);
        String date = m.group(5);
        String time = m.group(6);
        String path = m.group(7);
        String parentPath = Filesystem.dirname(path);
        String name = Filesystem.basename(path);
        Directory parent = parentPath == null ? null : (Directory)fs.get(parentPath);
        return new Directory(parent, name, FileMode.parse(perm), owner, group, parseCalendar(date, time), Long.parseLong(size));
    }

    private Regular addRegular(Filesystem fs, Matcher m) {
        String perm = m.group(1);
        String owner = m.group(2);
        String group = m.group(3);
        String size = m.group(4);
        String date = m.group(5);
        String time = m.group(6);
        String path = m.group(7);
        String parentPath = Filesystem.dirname(path);
        String name = Filesystem.basename(path);
        Directory parent = parentPath == null ? null : (Directory)fs.get(parentPath);
        return new Regular(parent, name, FileMode.parse(perm), owner, group, parseCalendar(date, time), Long.parseLong(size));
    }

    private Symlink addSymlink(Filesystem fs, Matcher m) {
        String perm = m.group(1);
        String owner = m.group(2);
        String group = m.group(3);
        String date = m.group(5);
        String time = m.group(6);
        String path = m.group(7);
        String link = m.group(8);
        String parentPath = Filesystem.dirname(path);
        String name = Filesystem.basename(path);
        Directory parent = parentPath == null ? null : (Directory)fs.get(parentPath);
        return new Symlink(parent, name, FileMode.parse(perm), owner, group, parseCalendar(date, time), link, fs);
    }

    private CharDevice addCharDevice(Filesystem fs, Matcher m) {
        String perm = m.group(1);
        String owner = m.group(2);
        String group = m.group(3);
        String major = m.group(4);
        String minor = m.group(5);
        String date = m.group(6);
        String time = m.group(7);
        String path = m.group(8);
        String parentPath = Filesystem.dirname(path);
        String name = Filesystem.basename(path);
        Directory parent = parentPath == null ? null : (Directory)fs.get(parentPath);
        return new CharDevice(parent, name, FileMode.parse(perm), owner, group, parseCalendar(date, time), Integer.parseInt(major), Integer.parseInt(minor));
    }

    private BlockDevice addBlockDevice(Filesystem fs, Matcher m) {
        String perm = m.group(1);
        String owner = m.group(2);
        String group = m.group(3);
        String major = m.group(4);
        String minor = m.group(5);
        String date = m.group(6);
        String time = m.group(7);
        String path = m.group(8);
        String parentPath = Filesystem.dirname(path);
        String name = Filesystem.basename(path);
        Directory parent = parentPath == null ? null : (Directory)fs.get(parentPath);
        return new BlockDevice(parent, name, FileMode.parse(perm), owner, group, parseCalendar(date, time), Integer.parseInt(major), Integer.parseInt(minor));
    }

    public Filesystem extract(File file) throws IOException, FileNotFoundException {
        if (!file.exists()) {
            throw new FileNotFoundException(file.getPath());
        }

        Filesystem fs = null;

        Pattern filePattern = Pattern.compile("^.([^\\s]{9})\\s+([^/]+)/([^\\s]+)\\s+(\\d+)\\s+([^\\s]+) ([^\\s]+) ROOT_FS(.*)$");
        Pattern symlinkPattern = Pattern.compile("^.([^\\s]{9})\\s+([^/]+)/([^\\s]+)\\s+(\\d+)\\s+([^\\s]+) ([^\\s]+) ROOT_FS(.*) -> (.*)$");
        Pattern devicePattern = Pattern.compile("^.([^\\s]{9})\\s+([^/]+)/([^\\s]+)\\s+(\\d+),\\s+(\\d+)\\s+([^\\s]+) ([^\\s]+) ROOT_FS(.*)$");
        Matcher matcher;

        String lines[] = sasquatch.execute("-ll", "-d", "ROOT_FS", file.getPath());
        if (lines != null) {
            for (String line : lines) {
                if (line.length() > 0) {
                    char first = line.charAt(0);
                    matcher = null;

                    if (first == '-') {
                        if ((matcher = filePattern.matcher(line)) != null && matcher.matches()) {
                            addRegular(fs, matcher);
                        }
                    } else if (first == 'd') {
                        if ((matcher = filePattern.matcher(line)) != null && matcher.matches()) {
                            Directory res = addDirectory(fs, matcher);
                            if (fs == null) {
                                fs = new Filesystem(res);
                            }
                        }
                    } else if (first == 'l') {
                        if ((matcher = symlinkPattern.matcher(line)) != null && matcher.matches()) {
                            addSymlink(fs, matcher);
                        }
                    } else if (first == 'c') {
                        if ((matcher = devicePattern.matcher(line)) != null && matcher.matches()) {
                            addCharDevice(fs, matcher);
                        }
                    } else if (first == 'b') {
                        if ((matcher = devicePattern.matcher(line)) != null && matcher.matches()) {
                            addBlockDevice(fs, matcher);
                        }
                    }
                }
            }
        }
        return fs;
    }

    public Filesystem extract(String path) throws IOException, FileNotFoundException {
        return extract(new File(path));
    }

    public byte[] extract(File container, Regular file) throws IOException, FileNotFoundException {
        byte result[] = null;
        Path p = Files.createTempDirectory("abc");
        String root = p + "/root";
        if (sasquatch.execute("-d", root, container.getAbsolutePath(), file.getAbsolutePath()) != null) {
            File f = new File(root + file.getAbsolutePath());
            if (f.exists() && f.isFile()) {
                result = new byte[(int)f.length()];
                FileInputStream fileIn = new FileInputStream(f);
                if (fileIn.read(result) != result.length) {
                    result = null;
                }
                fileIn.close();
            }
        }
        p.toFile().delete();
        return result;
    }
}
