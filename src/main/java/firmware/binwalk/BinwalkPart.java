package firmware.binwalk;

import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;

public class BinwalkPart {
    private BinwalkAnalysis analysis;
    private long offset;
    private long size;
    private String type;
    private String additional;

    public BinwalkPart(BinwalkAnalysis analysis, long offset, long size, String type, String additional) {
        this.analysis = analysis;
        this.offset = offset;
        this.size = size;
        this.type = type;
        this.additional = additional;
    }

    protected File extract() throws IOException {
        File tmp = File.createTempFile("abc", null);
        FileOutputStream stream = new FileOutputStream(tmp);
        stream.write(analysis.read(this));
        stream.close();
        tmp.deleteOnExit();
        return tmp;
    }

    public BinwalkAnalysis getAnalysis() {
        return analysis;
    }

    public long getOffset() {
        return offset;
    }

    public long getSize() {
        return size;
    }

    public String getType() {
        return type;
    }

    public String getAdditional() {
        return additional;
    }

    public byte[] getContent() throws IOException {
        return analysis.read(this);
    }

    public String toString() {
        return offset + "-" + (offset + size) + " : " + type + " : " + additional;
    }
}
