package eVotingMachine.core;

import static utils.MessageTools.first;
import static utils.MessageTools.second;

import funct.pkisig.Verifier;
import lib.network.NetworkError;
import lib.network.NetworkServer;

public class BulletinBoard
{
	Verifier verifier;
	EntryQueue entryLog;
	
	//FIXME: ONLY FOR TESTING
	private static byte[] lastMessage;
	
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
			lastMessage=request; //FIXME: only for testing
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
	
	//FIXME: ONLY FOR TESTING
	public byte[] getLastReceivedMessage()
	{
		return lastMessage;
	}
	
}
