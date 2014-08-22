package de.uni.trier.infsec.lib.time;

import de.uni.trier.infsec.environment.Environment;

public class Timestamp {

        /*@ public behaviour
          @ requires Environment.inputValues != null && 0 <= Environment.inputCounter;
          @ assignable Environment.inputCounter;
          @ diverges true;
          @ signals_only ArrayIndexOutOfBoundsException;
          @ ensures Environment.inputValues != null && 0 <= Environment.inputCounter
          @     && (\forall Object o; !\fresh(o));
          @ signals (ArrayIndexOutOfBoundsException e) Environment.inputValues != null
          @                                             && 0 <= Environment.inputCounter;
          @*/
	public static /*@ helper @*/ long get() {
		return 	Environment.untrustedInput();
	}

}