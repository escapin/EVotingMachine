package lib.time;

import environment.Environment;

public class Timestamp {
	
	public static long get() {
		return Environment.untrustedInputLong();
	}
	
}
