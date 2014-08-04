package de.uni.trier.infsec.environment;

public class Environment {

	private static boolean result; // the LOW variable

	private static int [] inputValues = {1,7,3}; // just an example
	private static int inputCounter = 0;
	
    public static int untrustedInput()
    {
    	return inputValues[inputCounter++];
	}
    
		
    public synchronized static void untrustedOutput(long x)
    {
		if (untrustedInput()==0) {
			result = (x==untrustedInput());
			throw new Error();  // abort
		}
	}
    
    public static byte[] untrustedInputMessage()
    {
		long llen = untrustedInput();
		int len = (int) llen;
		if (llen<0 || len!=llen) // check whether casting to int has changed its value
			return null;
		byte[] returnval = new byte[len];
		for (int i = 0; i < len; i++) {
			returnval[i] = (byte) Environment.untrustedInput();
		}
		return returnval;    
    }
    
    public static byte[][] untrustedInputMessages(int N)
    {
    	byte[][] output = new byte[N][];
    	for(int i=0;i<N;i++)
    		output[i]=untrustedInputMessage();
    	return output;
    }
    
    public static int[] untrustedInputArray(int N)
    {
    	int[] output = new int[N];
    	for(int i=0;i<N;i++)
    		output[i]=untrustedInput();
    	return output;
    }	
    
    public static void untrustedOutputMessage(byte[] t)
    {
    	untrustedOutput(t.length);
		for (int i = 0; i < t.length; i++) {
			untrustedOutput(t[i]);
		}
    }
    
    public static void untrustedOutputString(String s)
    {
    	untrustedOutput(s.length());
    	for (int i = 0; i < s.length(); i++) {
    		untrustedOutput((long)s.charAt(i));
    	}
    }
}        
