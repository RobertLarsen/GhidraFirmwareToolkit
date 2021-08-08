package firmware.fs;

public class Filesystem {
    private Directory root;

    public Filesystem(Directory root) {
        this.root = root;
    }

    public Directory getRoot() {
        return root;
    }

    public File get(String path) {
        Directory cur = root;

        String parts[] = path.split("/");
        for (int i = 1; i < parts.length - 1; i++) {
            cur = (Directory)cur.get(parts[i]);
        }
        return parts.length > 1 ? cur.get(parts[parts.length - 1]) : cur;
    }

    public static String basename(String path) {
        int lastPathSeparator = path.lastIndexOf('/');
        return path.substring(lastPathSeparator + 1);
    }

    public static String dirname(String path) {
        int lastPathSeparator = path.lastIndexOf('/');

        return lastPathSeparator < 0 ? null : path.substring(0, lastPathSeparator);
    }

    public File resolveDeep(Symlink link) {
        File result = link;
        while (result instanceof Symlink) {
            result = resolve((Symlink)result);
        }
        return result;
    }

    public File resolve(Symlink link) {
        if (link.getLink().equals("/")) {
            return getRoot();
        }

        File current;
        String parts[];

        if (link.getLink().charAt(0) == '/') {
            current = getRoot();
            parts = link.getLink().substring(1).split("/");
        } else {
            current = link.getParent();
            parts = link.getLink().split("/");
        }

        for (int i = 0; i < parts.length && current != null; i++) {
            if (!(current instanceof Directory)) {
                current = null;
                break;
            }
            if (parts[i].equals("..")) {
                current = current.getParent();
            } else if (parts[i].equals(".") == false) {
                current = ((Directory)current).get(parts[i]);
            }
        }
        return current;
    }
}
