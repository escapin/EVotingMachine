package de.uni.trier.infsec.utils;


public class MessageTools {

	/*@ public normal_behaviour
	  @ ensures ((\result == null) <==> (message == null))
	  @ 	&& (\result != null ==>
	  @ 			(\fresh(\result) && \result.length == message.length
	  @ 				&& \result != message
	  @ 				&& (\forall int i; 0 <= i && i < message.length;
	  @ 									\result[i] == message[i])))
	  @ 	&& (\forall Object o; o != \result; !\fresh(o));
	  @*/
    public static /*@ pure helper nullable @*/ byte[] copyOf(/*@ nullable @*/ byte[] message) {
        if (message==null) return null;
        byte[] copy = new byte[message.length];
        /*@ loop_invariant 0 <= i && i <= message.length
          @ 			&& copy != null && copy != message && \fresh(copy)
          @ 			&& copy.length == message.length
          @ 			&& (\forall int j; 0 <= j && j < i; copy[j] == message[j])
          @ 			&& (\forall Object o; o != copy; !\fresh(o));
          @ assignable copy[*];
          @ decreases message.length - i;
          @*/
        for (int i = 0; i < message.length; i++) {
            copy[i] = message[i];
        }
        return copy;
    }

    public static boolean equal(byte[] a, byte[] b) {
        if( a.length != b.length ) return false;
        for( int i=0; i<a.length; ++i)
            if( a[i] != b[i] ) return false;
        return true;
    }

    public static byte[] getZeroMessage(int messageSize) {
        byte[] zeroVector = new byte[messageSize];
        for (int i = 0; i < zeroVector.length; i++) {
            zeroVector[i] = 0x00;
        }
        return zeroVector;
    }

    /**
     * Concatenates messages in a way that makes it possible to unambiguously
     * split the message into the original messages (it adds length of the
     * first message at the beginning of the returned message).
     */
    /*@ public behaviour
      @ diverges true;
      @ signals_only NullPointerException;
      @ ensures \typeof(\result) == \type(byte[])
      @ 		&& ((m1 != null && m2 != null)
      @ 			==> (\result.length == m1.length + m2.length + 4))
      @         && \fresh(\result)
      @         && (\forall Object o; \typeof(o) != \type(byte[]); !\fresh(o));
      @ signals (NullPointerException e) true;
      @*/
    public static /*@ pure helper @*/ byte[] concatenate(/*@ nullable @*/ byte[] m1,
														 /*@ nullable @*/ byte[] m2) {
        // Concatenated Message --> byte[0-3] = Integer, Length of Message 1
        byte[] out = new byte[m1.length + m2.length + 4];

        // 4 bytes for length
        byte[] len = intToByteArray(m1.length);

        // copy all bytes to output array
        int j = 0;
        int i = 0;
        /*@ loop_invariant 0 <= i && len != null && out != null && m1 != null && m2 != null
          @             && \typeof(out) == \type(byte[]) && \typeof(len) == \type(byte[])
          @             && 0 <= j && j <= len.length && j <= out.length
          @             && len.length == 4 && out.length == m1.length + m2.length + 4
          @             && j == i && (\forall Object o; o != out && o != len; !\fresh(o));
          @ assignable out[*], j;
          @ decreases len.length - i;
          @*/
        for( i=0; i<len.length; ++i ) out[j++] = len[i];
        /*@ loop_invariant 0 <= i && m1 != null && out != null && m1 != null && m2 != null
          @             && \typeof(out) == \type(byte[]) && \typeof(len) == \type(byte[])
          @             && 4 <= j && j <= m1.length + 4 && j <= out.length
          @             && out.length == m1.length + m2.length + 4
          @             && j == i + 4 && (\forall Object o; o != out && o != len; !\fresh(o));
          @ assignable out[*], j;
          @ decreases m1.length - i;
          @*/
        for( i=0; i<m1.length;  ++i ) out[j++] = m1[i];
        /*@ loop_invariant 0 <= i && m2 != null && out != null && m1 != null && m2 != null
          @             && \typeof(out) == \type(byte[]) && \typeof(len) == \type(byte[])
          @             && m1.length + 4 <= j && j <= m2.length + m1.length + 4 && j <= out.length
          @             && out.length == m1.length + m2.length + 4
          @             && j == i + m1.length + 4 && (\forall Object o; o != out && o != len; !\fresh(o));
          @ assignable out[*], j;
          @ decreases m2.length - i;
          @*/
        for( i=0; i<m2.length;  ++i ) out[j++] = m2[i];

        return out;
    }

    /**
     * Simply concatenates the messages (without adding any information for
     * de-concatenation).
     */
    public static byte[] raw_concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        int j = 0;
        for( int i=0; i<a.length; ++i ) result[j++] = a[i];
        for( int i=0; i<b.length; ++i ) result[j++] = b[i];
        return result;
    }

    /**
     * Projection of the message to its two parts (part 1 = position 0, part 2 = position 1) Structure of the expected data: 1 Byte Identifier [0x01], 4 Byte
     * length of m1, m1, m2
     */
    /*@ private normal_behaviour
      @ ensures \fresh(\result);
      @*/
    private static /*@ pure helper @*/ byte[] project(/*@ nullable @*/ byte[] message, int position) {
        try {
            int len = byteArrayToInt(message);
            if (len > (message.length - 4)) return new byte[]{}; // Something is wrong with the message!
            if (position == 0) {
                byte[] m1 = new byte[len];
                /*@ loop_invariant 0 <= i && i <= len && \fresh(m1) && m1 != len
                  @ 			&& (\forall Object o; o != m1; !\fresh(o))
                  @ 			&& m1.length == len && len <= message.length - 4
                  @ 			&& (\forall int j; 0 <= j && j < i; m1[j] == message[j + 4]);
                  @ assignable m1[*];
                  @ decreases len - i;
                  @*/
                for (int i = 0; i < len; i ++) m1[i] = message[i + 4];
                return m1;
            } else if (position == 1) {
                byte[] m2 = new byte[message.length - len - 4];
                /*@ loop_invariant 0 <= i && i <= message.length - len - 4 && \fresh(m2)
                  @ 			&& (\forall Object o; o != m2; !\fresh(o)) && m2 != len
                  @ 			&& m2.length == message.length - len - 4
                  @ 			&& len <= message.length - 4
                  @ 			&& (\forall int j; 0 <= j && j < i; m2[j] == message[j + 4 + len]);
                  @ assignable m2[*];
                  @ decreases message.length - len - 4 - i;
                  @*/
                for (int i = 0; i < message.length - len - 4; i ++) m2[i] = message[i + 4 + len];
                return m2;
            } else return new byte[]{};
        } catch (Exception e) {
            return new byte[]{};
        }
    }

    /*@ private normal_behaviour
      @ ensures \fresh(\result);
      @*/
    public static /*@ pure helper @*/ byte[] first(/*@ nullable @*/ byte[] in) {
        return project(in, 0);
    }

    /*@ private normal_behaviour
      @ ensures \fresh(\result);
      @*/
    public static /*@ pure helper @*/ byte[] second(/*@ nullable @*/ byte[] in) {
        return project(in, 1);
    }

    /*@ public behaviour
      @ signals_only NullPointerException, ArrayIndexOutOfBoundsException;
      @ diverges true;
	  @ ensures true;
	  @ signals (NullPointerException e) true;
	  @ signals (ArrayIndexOutOfBoundsException e) true;
	  @*/
    public static final /*@ pure helper @*/ int byteArrayToInt(/*@ nullable @*/ byte [] b) {
        return (b[0]  << 24)
                + ((b[1] & 0xFF) << 16)
                + ((b[2] & 0xFF) << 8)
                + (b[3] & 0xFF);
    }


    /*@ public normal_behaviour
      @ ensures \result.length == 4 && \fresh(\result) && \typeof(\result) == \type(byte[])
      @         && (\forall Object o; o != \result; !\fresh(o));
      @*/
    public static final /*@ pure helper @*/ byte[] intToByteArray(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value};
    }


    /*@ public normal_behaviour
      @ ensures \result.length == 8 && \fresh(\result)
      @ 	&& (\forall Object o; o != \result; !\fresh(o));
      @*/
    public static final /*@ pure helper @*/ byte[] longToByteArray(long value){
        byte[] b = new byte[8];
        /*@ loop_invariant 0 <= i && b != null && b.length == 8
          @             && (\forall Object o; o != b; !\fresh(o));
          @ assignable b[*];
          @ decreases b.length - i;
          @*/
        for (int i = 0; i < b.length; i++) {
            int offset = (b.length - 1 - i) * 8;
            b[i] = (byte) ((value >>> offset) & 0xFF);
        }
        return b;
    }

    public static final long byteArrayToLong(byte [] b){
        long value=0;
        for(int i=0; i<b.length; i++){
            int offset=(b.length -1 - i) * 8;
            value += (long) (b[i] & 0xFF) << offset;
        }
        return value;
    }
}