package de.uni.trier.infsec.environment;

class Node 
{
	long value;
	Node next;
	
	Node(long value, Node next){
		this.value = value; 
		this.next = next;
	}
}

public class Environment {

    // TODO: only primitive types are changed
	private static boolean result; // the LOW variable
	
	private static Node list = null;
	private static boolean listInitialized = false;
		
	private static Node initialValue()
	{
		// Unknown specification of the following form:
		// return new Node(U1, new Node(U2, ...));
		// where U1, U2, ...Un are constant integers.
		return new Node(1, new Node(7,null));  // just an example
	}

    public synchronized static long untrustedInputLong()
    {
    	if (!listInitialized) {
    		list = initialValue();
    	    listInitialized = true;        
    	}
    	if (list==null) 
    		return 0;
    	long tmp = list.value;
    	list = list.next;
    	return tmp;
	}
    
    public static int untrustedInput() {
    	return (int)untrustedInputLong();
    }
		
    public synchronized static void untrustedOutput(long x)
    {
		if (untrustedInputLong()==0) {
			result = (x==untrustedInputLong());
			// System.out.println(result);
			throw new Error();  // abort
		}
	}
    
    public static byte[] untrustedInputMessage()
    {
		long llen = untrustedInputLong();
		int len = (int) llen;
		if (llen<0 || len!=llen) // check whether casting to int has changed its value
			return null;
		byte[] returnval = new byte[len];
		for (int i = 0; i < len; i++) {
			returnval[i] = (byte) Environment.untrustedInputLong();
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
