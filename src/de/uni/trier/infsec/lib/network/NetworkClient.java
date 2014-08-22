package de.uni.trier.infsec.lib.network;

import de.uni.trier.infsec.environment.Environment;

public class NetworkClient {

    /*@ public behaviour
      @ requires Environment.inputValues != null && 0 <= Environment.inputCounter;
      @ assignable Environment.inputCounter, Environment.result;
      @ signals_only NetworkError, ArrayIndexOutOfBoundsException, Error;
      @ diverges true;
      @ ensures Environment.inputValues != null && 0 <= Environment.inputCounter;
      @ signals (NetworkError e) Environment.inputValues != null && 0 <= Environment.inputCounter;
      @ signals (ArrayIndexOutOfBoundsException e)
      @                 Environment.inputValues != null && 0 <= Environment.inputCounter;
      @ signals (Error e) Environment.inputValues != null && 0 <= Environment.inputCounter;
      @*/
    public static /*@ helper @*/ void send(byte[] message, String server, int port)
            throws NetworkError {
        // input
        Environment.untrustedOutput(0x2301);
        Environment.untrustedOutputMessage(message);
        Environment.untrustedOutputString(server);
        Environment.untrustedOutput(port);
        // output
        if ( Environment.untrustedInput()==0 ) throw new NetworkError();
    }

    /*@ public behaviour
      @ requires Environment.inputValues != null && 0 <= Environment.inputCounter;
      @ assignable Environment.inputCounter, Environment.result;
      @ signals_only NetworkError, ArrayIndexOutOfBoundsException, Error;
      @ diverges true;
      @ ensures true;
      @ signals (NetworkError e) Environment.inputValues != null && 0 <= Environment.inputCounter;
      @ signals (ArrayIndexOutOfBoundsException e)
      @                 Environment.inputValues != null && 0 <= Environment.inputCounter;
      @ signals (Error e) Environment.inputValues != null && 0 <= Environment.inputCounter;
      @*/
    public static /*@ helper nullable @*/ byte[] sendRequest(byte[] message, String server, int port)
            throws NetworkError {
        // input
        Environment.untrustedOutput(0x2302);
        Environment.untrustedOutputMessage(message);
        Environment.untrustedOutputString(server);
        Environment.untrustedOutput(port);
        // output
        if ( Environment.untrustedInput()==0 ) throw new NetworkError();
        return Environment.untrustedInputMessage();
    }
}