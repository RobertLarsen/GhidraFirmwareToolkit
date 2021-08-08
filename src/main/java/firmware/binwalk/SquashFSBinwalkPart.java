package firmware.binwalk;

import java.io.IOException;
import firmware.fs.Filesystem;

public class SquashFSBinwalkPart extends BinwalkPart {
    public SquashFSBinwalkPart(BinwalkAnalysis analysis, long offset, long size, String type, String additional) {
        super(analysis, offset, size, type, additional);
    }

    public Filesystem extractFilesystem() throws IOException {
        Sasquatch sasquatch = new Sasquatch();
        return sasquatch.extract(this.extract());
    }
}
