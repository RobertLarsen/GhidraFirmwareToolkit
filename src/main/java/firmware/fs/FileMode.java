package firmware.fs;

public class FileMode {
    private int mode;

    public FileMode(int mode) {
        this.mode = mode;
    }

    public int getMode() {
        return mode;
    }

    public String toString() {
        return triple((mode >> 6) & 7) +
               triple((mode >> 3) & 7) +
               triple((mode >> 0) & 7);
    }

    private static String triple(int perm) {
        return (((perm & 4) == 0) ? "-" : "r") +
               (((perm & 2) == 0) ? "-" : "w") +
               (((perm & 1) == 0) ? "-" : "x");
    }

    private static int parseTriple(String triple) {
        int mode = 0;
        if (triple.charAt(0) == 'r') {
            mode |= 1 << 2;
        }
        if (triple.charAt(1) == 'w') {
            mode |= 1 << 1;
        }
        if (triple.charAt(2) == 'x') {
            mode |= 1 << 0;
        }
        return mode;
    }

    public static FileMode parse(String s) {
        return new FileMode((parseTriple(s.substring(0, 3)) << 6) |
                            (parseTriple(s.substring(3, 6)) << 3) |
                            (parseTriple(s.substring(6, 9)) << 0));
    }
}
