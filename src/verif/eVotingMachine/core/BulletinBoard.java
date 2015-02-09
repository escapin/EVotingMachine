package verif.eVotingMachine.core;

import verif.functionalities.pkisig.Verifier;
import verif.lib.network.NetworkError;
import static verif.utils.MessageTools.first;
import static verif.utils.MessageTools.second;

public class BulletinBoard
{
	/*@ spec_public @*/ Verifier verifier;
	/*@ spec_public @*/ EntryQueue entryLog;


	public BulletinBoard(Verifier verifier) throws NetworkError
	{
		this.verifier=verifier;
		entryLog= new EntryQueue();
	}

	/*
	 * Reads a message, checks if it comes from the voting machine, and, 
	 * if this is the case, adds it to the maintained list of messages.
	 */
	/*@ public behaviour
	  @ requires entryLog != null && verifier != null;
	  @ diverges true;
	  @ ensures true;
	  @ signals (NetworkError e) true;
	  @ signals (NullPointerException e) true;
	  @*/
	public /*@ strictly_pure helper @// to be proven with JOANA */ void
		onPost(/*@ nullable @*/byte[] request) throws NetworkError
	{
		byte[] message = first(request);
		byte[] signature = second(request);

		if(verifier.verify(signature, message))
		{
			entryLog.add(request);
		}
	}

	/*
	 * Output its content, that is the concatenation of
	 * all the message in the maintained list of messages.
	 */
	/*@ public behaviour
	  @ requires entryLog != null && verifier != null;
	  @ diverges true;
	  @ ensures true;
	  @ signals (NetworkError e) true;
	  @ signals (NullPointerException e) true;
	  @*/
	public /*@ pure helper nullable @*/ byte[] onRequestContent() throws NetworkError
	{
		return entryLog.getEntries();
	}
}