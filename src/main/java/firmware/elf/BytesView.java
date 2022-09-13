package firmware.elf;

public class BytesView {
    public enum Endian {
        LITTLE, BIG
    }

    private byte bytes[];
    private Endian endian;

    public BytesView(byte bytes[], Endian endian) {
        this.bytes = bytes;
        this.endian = endian;
    }

    public BytesView(byte bytes[]) {
        this(bytes, Endian.LITTLE);
    }

    private long decode(byte ... bytes) {
        long res = 0;
        for (byte b : bytes) {
            res = (res << 8) | (b & 0xffl);
        }
        return res;
    }

    private void encode(Endian endian, int idx, byte ... bytes) {
        if (endian == Endian.BIG) {
            System.arraycopy(bytes, 0, this.bytes, idx, bytes.length);
        } else {
            for (int i = 0; i < bytes.length; i++) {
                this.bytes[idx + i] = bytes[bytes.length - 1 - i];
            }
        }
    }

    public Endian getEndian() {
        return endian;
    }

    public void setEndian(Endian endian) {
        this.endian = endian;
    }

    public int size() {
        return bytes.length;
    }

    public byte[] asByteArray() {
        return getBytesAt(0, bytes.length);
    }

    public byte[] readBytesAt(byte dest[], int sourceIndex, int length) {
        System.arraycopy(bytes, sourceIndex, dest, 0, length);
        return dest;
    }

    public byte[] readBytesAt(byte dest[], int sourceIndex) {
        return readBytesAt(dest, sourceIndex, dest.length);
    }

    public byte[] getBytesAt(int idx, int length) {
        byte dest[] = new byte[length];
        return readBytesAt(dest, idx, length);
    }

    public byte getByteAt(int idx) {
        return bytes[idx];
    }

    public void setByteAt(byte value, int idx) {
        bytes[idx] = value;
    }

    public short getUnsignedByteAt(int idx) {
        return (short)(bytes[idx] & 0xff);
    }

    public void setUnsignedByteAt(short value, int idx) {
        bytes[idx] = (byte)(value & 0xff);
    }

    public short getShortAt(int idx, Endian endian) {
        return (short)(endian == Endian.BIG ?
            decode(bytes[idx + 0], bytes[idx + 1]) & 0xffff:
            decode(bytes[idx + 1], bytes[idx + 0]) & 0xffff);
    }

    public void setShortAt(short value, int idx, Endian endian) {
        encode(endian, idx, (byte)((value >>> 8) & 0xff), (byte)((value >>> 0) & 0xff));
    }

    public short getShortAt(int idx) {
        return getShortAt(idx, endian);
    }

    public void setShortAt(short value, int idx) {
        setShortAt(value, idx, endian);
    }

    public int getUnsignedShortAt(int idx, Endian endian) {
        return (int)(endian == Endian.BIG ?
            decode(bytes[idx + 0], bytes[idx + 1]) & 0xffff:
            decode(bytes[idx + 1], bytes[idx + 0]) & 0xffff);
    }

    public void setUnsignedShortAt(int value, int idx, Endian endian) {
        encode(endian, idx, (byte)((value >>> 8) & 0xff), (byte)((value >>> 0) & 0xff));
    }

    public int getUnsignedShortAt(int idx) {
        return getShortAt(idx, endian);
    }

    public void setUnsignedShortAt(int value, int idx) {
        setUnsignedShortAt(value, idx, endian);
    }

    public int getIntAt(int idx, Endian endian) {
        return (int)(endian == Endian.BIG ?
            decode(bytes[idx + 0], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]) & 0xffffffff :
            decode(bytes[idx + 3], bytes[idx + 2], bytes[idx + 1], bytes[idx + 0]) & 0xffffffff);
    }

    public void setIntAt(int value, int idx, Endian endian) {
        encode(endian, idx, (byte)((value >>> 24) & 0xff), (byte)((value >>> 16) & 0xff), (byte)((value >>> 8) & 0xff), (byte)((value >>> 0) & 0xff));
    }

    public int getIntAt(int idx) {
        return getIntAt(idx, endian);
    }

    public void setIntAt(int value, int idx) {
        setIntAt(value, idx, endian);
    }

    public long getUnsignedIntAt(int idx, Endian endian) {
        return (long)(endian == Endian.BIG ?
            decode(bytes[idx + 0], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]) & 0xffffffff :
            decode(bytes[idx + 3], bytes[idx + 2], bytes[idx + 1], bytes[idx + 0]) & 0xffffffff);
    }

    public void setUnsignedIntAt(long value, int idx, Endian endian) {
        encode(endian, idx, (byte)((value >>> 24) & 0xff), (byte)((value >>> 16) & 0xff), (byte)((value >>> 8) & 0xff), (byte)((value >>> 0) & 0xff));
    }

    public long getUnsignedIntAt(int idx) {
        return getUnsignedIntAt(idx, endian);
    }

    public void setUnsignedIntAt(long value, int idx) {
        setUnsignedIntAt(value, idx, endian);
    }

    public long getLongAt(int idx, Endian endian) {
        return endian == Endian.BIG ?
            decode(bytes[idx + 0], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3], bytes[idx + 4], bytes[idx + 5], bytes[idx + 6], bytes[idx + 7]) :
            decode(bytes[idx + 7], bytes[idx + 6], bytes[idx + 5], bytes[idx + 4], bytes[idx + 3], bytes[idx + 2], bytes[idx + 1], bytes[idx + 0]);
    }

    public void setLongAt(long value, int idx, Endian endian) {
        encode(endian, idx, (byte)((value >>> 56) & 0xff), (byte)((value >>> 48) & 0xff), (byte)((value >>> 40) & 0xff), (byte)((value >>> 32) & 0xff), (byte)((value >>> 24) & 0xff), (byte)((value >>> 16) & 0xff), (byte)((value >>> 8) & 0xff), (byte)((value >>> 0) & 0xff));
    }

    public long getLongAt(int idx) {
        return getLongAt(idx, endian);
    }

    public void setLongAt(long value, int idx) {
        setLongAt(value, idx, endian);
    }

    private static void test(BytesView v, Endian endian) {
        String e = endian == Endian.BIG ? "BE" : "LE";
        System.out.println(String.format("Byte   %s: 0x%02x %d", e, v.getByteAt(0), v.getByteAt(0)));
        System.out.println(String.format("UByte  %s: 0x%02x %d", e, v.getUnsignedByteAt(0), v.getUnsignedByteAt(0)));
        System.out.println(String.format("Short  %s: 0x%04x %d", e, v.getShortAt(0, endian), v.getShortAt(0, endian)));
        System.out.println(String.format("UShort %s: 0x%04x %d", e, v.getUnsignedShortAt(0, endian), v.getUnsignedShortAt(0, endian)));
        System.out.println(String.format("Int    %s: 0x%08x %d", e, v.getIntAt(0, endian), v.getIntAt(0, endian)));
        System.out.println(String.format("UInt   %s: 0x%08x %d", e, v.getUnsignedIntAt(0, endian), v.getUnsignedIntAt(0, endian)));
        System.out.println(String.format("Long   %s: 0x%016x %d", e, v.getLongAt(0, endian), v.getLongAt(0, endian)));
    }

    public static void main(String args[]) {
        BytesView v = new BytesView(new byte[] {(byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef, (byte)0xc0, (byte)0xde, (byte)0xba, (byte)0xbe});
        test(v, Endian.BIG);
        test(v, Endian.LITTLE);

        v.setLongAt(0x8899aabbccddeeffl, 0, Endian.BIG);
        System.out.println(String.format("Long 0x%016x 0x%016x", v.getLongAt(0, Endian.BIG), v.getLongAt(0, Endian.LITTLE)));

        v.setLongAt(0x8899aabbccddeeffl, 0, Endian.LITTLE);
        System.out.println(String.format("Long 0x%016x 0x%016x", v.getLongAt(0, Endian.BIG), v.getLongAt(0, Endian.LITTLE)));

        v.setIntAt(0xaabbccdd, 0, Endian.BIG);
        System.out.println(String.format("Int 0x%08x 0x%08x", v.getIntAt(0, Endian.BIG), v.getIntAt(0, Endian.LITTLE)));

        v.setIntAt(0xaabbccdd, 0, Endian.LITTLE);
        System.out.println(String.format("Int 0x%08x 0x%08x", v.getIntAt(0, Endian.BIG), v.getIntAt(0, Endian.LITTLE)));

        v.setShortAt((short)0xabcd, 0, Endian.BIG);
        System.out.println(String.format("Short 0x%04x 0x%04x", v.getShortAt(0, Endian.BIG), v.getShortAt(0, Endian.LITTLE)));

        v.setShortAt((short)0xabcd, 0, Endian.LITTLE);
        System.out.println(String.format("Short 0x%04x 0x%04x", v.getShortAt(0, Endian.BIG), v.getShortAt(0, Endian.LITTLE)));
    }
}
