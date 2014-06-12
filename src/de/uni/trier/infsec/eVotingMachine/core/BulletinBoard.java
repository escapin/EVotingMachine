package de.uni.trier.infsec.eVotingMachine.core;

import de.uni.trier.infsec.functionalities.pkienc.Decryptor;
import de.uni.trier.infsec.functionalities.pkisig.Verifier;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.network.NetworkServer;

import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;

public class BulletinBoard
{
	Decryptor decryptor;
	Verifier verifier;
	EntryQueue entryLog;
	
	//FIXME: ONLY FOR TESTING
	private static byte[] lastMessage;
	
	public BulletinBoard(Decryptor decryptor, Verifier verifier) throws NetworkError
	{
		this.decryptor=decryptor;
		this.verifier=verifier;
		entryLog= new EntryQueue();
		NetworkServer.listenForRequests(Params.LISTEN_PORT_BBOARD);
	}
	
	/*
	 * Reads a message, checks if it comes from the voting machine, and, 
	 * if this is the case, adds it to the maintained list of messages.
	 */
	public void onPost() throws NetworkError
	{
		byte[] request=null;
		do{ 
			request=NetworkServer.nextRequest(Params.LISTEN_PORT_BBOARD);
		} while(request==null);
		
		byte[] message = first(request);
		byte[] signature = second(request);
		
		//System.out.println("ciao");
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
