package verif.lib.time;

import verif.environment.Environment;

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