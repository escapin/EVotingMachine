package de.uni.trier.infsec.lib.time;

import de.uni.trier.infsec.environment.Environment;

public class Timestamp {

        /*@ public behavior
          @ assignable Environment.inputCounter;
          @ diverges true;
          @ ensures true;
          @*/
	public static /*@ helper @*/ long get() {
		return 	Environment.untrustedInput();
	}

}