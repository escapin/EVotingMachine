package de.uni.trier.infsec.environment;

public class Environment {

	private /*@ spec_public @*/ static boolean result; // the LOW variable

	private /*@ spec_public @*/ static int [] inputValues = {1,7,3}; // just an example
	private /*@ spec_public @*/ static int inputCounter = 0;


	/*@ public behavior
	  @ assignable inputCounter;
	  @ diverges true;
	  @ ensures true;
	  @*/
	public static /*@ helper @*/ int untrustedInput()
	{
		return inputValues[inputCounter++];
	}

	/*@ public behavior
	  @ diverges true;
	  @ assignable inputCounter;
	  @ ensures 0 <= \result && \result < n;
	  @*/
	public static /*@ helper @*/ int untrustedInput(int n)
	{
		int res = -1;
		/*@ loop_invariant true;
		  @ assignable inputCounter;
		  @*/
		while (res < 0 || res >= n) {
			res = untrustedInput();
		}
		return res;
	}

	/*@ public behavior
	  @ diverges true;
	  @ assignable inputCounter, result;
	  @ ensures true;
	  @*/
	public synchronized static /*@ helper @*/ void untrustedOutput(long x)
	{
		if (untrustedInput()==0) {
			result = (x==untrustedInput());
			throw new Error();  // abort
		}
	}

	/*@ public behavior
	  @ diverges true;
	  @ assignable inputCounter;
	  @ ensures true;
	  @*/
	public static /*@ helper nullable @*/ byte[] untrustedInputMessage()
	{
		long llen = untrustedInput();
		int len = (int) llen;
		if (llen<0 || len!=llen) // check whether casting to int has changed its value
			return null;
		byte[] returnval = new byte[len];
		/*@ loop_invariant true;
		  @ assignable inputCounter, returnval[*];
		  @*/
		for (int i = 0; i < len; i++) {
			returnval[i] = (byte) Environment.untrustedInput();
		}
		return returnval;
	}

	/*@ public behavior
	  @ diverges true;
	  @ assignable inputCounter;
	  @ ensures \result != null
	  @ 	&& \result.length == N  && \fresh(\result);
	  @*/
	public static /*@ helper nullable @*/ byte[][] untrustedInputMessages(int N)
	{
		byte[][] output = new byte[N][];
		/*@ loop_invariant true;
		  @ assignable inputCounter, output[*];
		  @*/
		for(int i=0;i<N;i++)
			output[i]=untrustedInputMessage();
		return output;
	}

	/*@ public behavior
	  @ diverges true;
	  @ assignable inputCounter;
	  @ ensures \result.length == N
	  @ 	&& \fresh(\result);
	  @*/
	public static /*@ helper @*/ int[] untrustedInputArray(int N)
	{
		int[] output = new int[N];
		/*@ loop_invariant 0 <= N
		  @ 		&& output.length == N && \fresh(output);
		  @ assignable inputCounter, output[*];
		  @*/
		for(int i=0;i<N;i++)
			output[i]=untrustedInput();
		return output;
	}

	/*@ public behavior
	  @ diverges true;
	  @ assignable inputCounter, result;
	  @ ensures true;
	  @*/
	public static /*@ helper @*/ void untrustedOutputMessage(/*@ nullable @*/byte[] t)
	{
		untrustedOutput(t.length);
		/*@ loop_invariant true;
		  @ assignable inputCounter, result;
		  @*/
		for (int i = 0; i < t.length; i++) {
			untrustedOutput(t[i]);
		}
	}

	/*@ public behavior
	  @ diverges true;
	  @ assignable inputCounter, result;
	  @ ensures true;
	  @*/
	public static /*@ helper @*/ void untrustedOutputString(String s)
	{
		untrustedOutput(s.length());
		/*@ loop_invariant true;
		  @ assignable inputCounter, result;
		  @*/
		for (int i = 0; i < s.length(); i++) {
			untrustedOutput(s.charAt(i));
		}
	}
}