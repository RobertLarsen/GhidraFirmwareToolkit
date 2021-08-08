package firmware.binwalk;

import java.io.InputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

public class ExecutableWrapper {
    private File executable;

    public ExecutableWrapper(File executable) throws FileNotFoundException {
        if (!executable.exists()) {
            throw new FileNotFoundException(executable.getPath());
        }
        this.executable = executable;
    }

    public ExecutableWrapper(String path) throws FileNotFoundException {
        this(new File(path));
    }

    public String[] execute(String ... args) throws IOException {
        String cmd[] = new String[args.length + 1];
        cmd[0] = executable.getPath();
        for (int i = 0; i < args.length; i++) {
            cmd[i + 1] = args[i];
        }
        Process p = Runtime.getRuntime().exec(cmd);
        try {
            InputStream in = p.getInputStream();
            if (in != null) {
                String out = firmware.ghidra.FirmwarePlugin.readString(in, "utf8");
                p.waitFor();
                if (p.exitValue() == 0) {
                    return out.split("\n");
                }
            }
        } catch (Exception ie) {
        }
        return null;
    }
}
