package de.uni.trier.infsec.lib.time;

import de.uni.trier.infsec.environment.Environment;

public class Timestamp {
	
	public static long get() {
		return Environment.untrustedInputLong();
	}
	
}
