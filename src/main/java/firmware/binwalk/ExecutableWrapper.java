package firmware.binwalk;

import java.io.InputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ByteArrayOutputStream;

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

    public static String readString(InputStream in, String charset) throws IOException {
        byte buffer[] = new byte[1024];
        int bytesRead;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while ((bytesRead = in.read(buffer)) > 0) {
            out.write(buffer, 0, bytesRead);
        }
        return new String(out.toByteArray(), charset);
    }

    public String[] execute(String ... args) throws IOException {
        String total;
        String cmd[] = new String[args.length + 1];
        cmd[0] = total = executable.getPath();
        for (int i = 0; i < args.length; i++) {
            total += " " + args[i];
            cmd[i + 1] = args[i];
        }
        Process p = Runtime.getRuntime().exec(cmd);
        try {
            InputStream in = p.getInputStream();
            if (in != null) {
                String out = readString(in, "utf8");
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
