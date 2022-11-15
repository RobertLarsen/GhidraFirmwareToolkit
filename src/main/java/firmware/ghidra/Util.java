package firmware.ghidra;

import ghidra.formats.gfilesystem.GFile;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.ObfuscatedFileByteProvider;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.formats.gfilesystem.RefdByteProvider;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.File;
import java.io.IOException;

public class Util {
    public final static File _getAsFile(ByteProvider provider) throws IOException {
        if (provider instanceof RefdByteProvider) {
            return ((RefdByteProvider)provider).getFile();
        } else if (provider instanceof ObfuscatedFileByteProvider) {
            return ((ObfuscatedFileByteProvider)provider).getFile();
        } else if (provider instanceof FileByteProvider) {
            return ((FileByteProvider)provider).getFile();
        } else if (provider instanceof FileBytesProvider) {
            return ((FileBytesProvider)provider).getFile();
        } else {
            return null;
        }
    }

    public final static File getAsFile(ByteProvider provider) throws IOException {
        File f = _getAsFile(provider);
        if (f == null) {
            f = File.createTempFile("afile-", ".fs");
            FileOutputStream out = new FileOutputStream(f);
            out.write(provider.readBytes(0, provider.length()));
            out.close();

        }
        return f;
    }

    public final static ByteProvider toByteProvider(InputStream stream, GFile file) throws IOException {
        byte array[] = new byte[(int)file.getLength()];
        stream.read(array);
        return new ByteArrayProvider(array, file.getFSRL());
    }
}
