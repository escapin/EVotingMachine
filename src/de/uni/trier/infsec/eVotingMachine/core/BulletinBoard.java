package de.uni.trier.infsec.eVotingMachine.core;

import de.uni.trier.infsec.functionalities.pkisig.Verifier;
import de.uni.trier.infsec.lib.network.NetworkError;

import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;

public class BulletinBoard
{
	Verifier verifier;
	EntryQueue entryLog;
	
	
	public BulletinBoard(Verifier verifier) throws NetworkError
	{
		this.verifier=verifier;
		entryLog= new EntryQueue();
	}
	
	/*
	 * Reads a message, checks if it comes from the voting machine, and, 
	 * if this is the case, adds it to the maintained list of messages.
	 */
	public void onPost(byte[] request) throws NetworkError
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
	public byte[] onRequestContent() throws NetworkError
	{
		return entryLog.getEntries();
	}
		
}
