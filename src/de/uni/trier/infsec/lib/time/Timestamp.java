package de.uni.trier.infsec.lib.time;

import de.uni.trier.infsec.environment.Environment;

public class Timestamp {

    // TODO: cannot be verified, since changes the environment
        /*@ public behavior
          @ assignable Environment.inputCounter;
          @ diverges true;
          @ signals_only ArrayIndexOutOfBoundsException;
          @ ensures true;
          @*/
	public static /*@ helper @*/ long get() {
		return 	Environment.untrustedInput();
	}

}