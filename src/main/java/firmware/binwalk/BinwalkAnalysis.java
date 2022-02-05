package firmware.binwalk;

import java.io.File;
import java.io.RandomAccessFile;
import java.io.IOException;
import java.util.LinkedList;
import java.util.Iterator;

public class BinwalkAnalysis implements Iterable<BinwalkPart> {
    private Binwalk owner;
    private File firmware;
    private LinkedList<BinwalkPart> parts;

    public BinwalkAnalysis(Binwalk owner, File firmware) {
        this.owner = owner;
        this.firmware = firmware;
        this.parts = new LinkedList<>();
    }

    public File getFirmware() {
        return firmware;
    }

    public Binwalk getOwner() {
        return owner;
    }

    public int count() {
        return parts.size();
    }

    public BinwalkPart get(int idx) {
        return parts.get(idx);
    }

    byte[] read(BinwalkPart part) throws IOException {
        byte result[] = new byte[(int)part.getSize()];
        RandomAccessFile r = new RandomAccessFile(firmware, "r");
        r.seek(part.getOffset());
        r.readFully(result);
        r.close();
        return result;
    }

    void add(BinwalkPart part) {
        parts.add(part);
    }

    void add(long offset, long size, String type, String additional) {
        if (type.equals("Squashfs filesystem")) {
            add(new SquashFSBinwalkPart(this, offset, size, type, additional));
        } else {
            add(new BinwalkPart(this, offset, size, type, additional));
        }
    }

    public Iterator<BinwalkPart> iterator() {
        return parts.iterator();
    }
}
