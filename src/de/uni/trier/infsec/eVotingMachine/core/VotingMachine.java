package de.uni.trier.infsec.eVotingMachine.core;

import java.util.Arrays;


import de.uni.trier.infsec.functionalities.pkienc.Decryptor;
import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;

import static de.uni.trier.infsec.utils.MessageTools.intToByteArray;
import static de.uni.trier.infsec.utils.MessageTools.longToByteArray;
import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.copyOf;


	


public class VotingMachine
{
	// CRYPTOGRAPHIC FUNCTIONALITIES
	private final Encryptor bb_encryptor;
	private final Signer signer;
	
	private int numberOfCandidates;
	private int[] votesForCandidates;
	private int operationCounter, voteCounter; 
	private EntryList entryLog;
	private byte[] lastBallot;
	
	public VotingMachine(int numberOfCandidates, Encryptor bb_encryptor, Signer signer)
	{
		this.numberOfCandidates=numberOfCandidates;
		this.bb_encryptor=bb_encryptor;
		this.signer=signer;
		votesForCandidates = new int[numberOfCandidates];
		entryLog = new EntryList();
		operationCounter=0;
		voteCounter=0;
	}
	
	
	
	public int collectBallot(int voterChoice) throws NetworkError, MalformedVote
	{
		if (voterChoice < 0 || voterChoice >= numberOfCandidates ) 
			throw new MalformedVote();
		
		votesForCandidates[voterChoice]++;
		voteCounter++;
		long timestamp = Utilities.getTimestamp();
		
		byte[] vote_voteCounter = concatenate(	
									intToByteArray(voterChoice),
									intToByteArray(voteCounter));
		byte[] ballot = concatenate(
									longToByteArray(timestamp),
									vote_voteCounter);
		
		// set this inner ballot as the last inner ballot
		lastBallot=copyOf(ballot);
		
		operationCounter++;
		createAndsendEntry(operationCounter, Params.VOTE, ballot);
		
		return operationCounter;
	}
	
	public void cancelLastBallot() throws NetworkError
	{
		if(lastBallot==null)
			return;
		
		operationCounter++;
		createAndsendEntry(operationCounter, Params.CANCEL, lastBallot);
		lastBallot=null;
	}
	
	
	public void publishResult()
	{
		
	}
	
	public void publishLog()
	{
		
	}
	
	
	
	/**
	 * Encrypt the payload, concatenate the operation counter, sign and send the message to the bullettin board.  
	 */
	private void createAndsendEntry(int operationCounter, byte[] tag, byte[] ballot) throws NetworkError{
		byte[] operationCouter_ballot= concatenate(
											intToByteArray(operationCounter),
											ballot);
		byte[] entry=concatenate(tag, operationCouter_ballot);
		// add the ballot to the log as an entry
		entryLog.add(operationCounter, copyOf(entry));
		
		// encrypt the entry
		byte[] encryptedEntry=bb_encryptor.encrypt(entry);
		byte[] msgToSign=concatenate(
									intToByteArray(operationCounter),
									encryptedEntry);
		
		byte[] signature = signer.sign(msgToSign);
		byte[] msgToSend = concatenate(msgToSign, signature);
		NetworkClient.send(msgToSend, Params.DEFAULT_HOST_BBOARD , Params.LISTEN_PORT_BBOARD);
	}
	
	@SuppressWarnings("serial")
	public class MalformedVote extends Exception{}
	
	/**
	 * List of labels.
	 * For each 'label' maintains an counter representing 
	 * how many times the label has been used.
	 */
	static private class EntryList {

		static class Node {
			public byte[] entry;
			public int operationCounter;
			public Node next;

			public Node(int operationCounter, byte[] entry) {
				this.entry = entry;
				this.operationCounter = operationCounter;
				this.next=null;
			}
		}

		private Node head, last = null;

		public void add(int operationCounter, byte[] entry) {
			Node newEntry=new Node(operationCounter, entry);
			if(head==null)
				head=last=newEntry;
			else {
				last.next=newEntry;
				last=newEntry;
			}
		}

		public byte[] get(int operationCounter) {
			for(Node n = head; n != null; n=n.next)
				if( n.operationCounter==operationCounter  )
					return n.entry;	
			return null;
		}
		
		public void remove(int operationCounter) {
			if(head.operationCounter==operationCounter)
				head=head.next;
			else{
				Node prec=head;
				for(Node curr=head.next; curr!=null;  curr=curr.next){
					if(curr.operationCounter==operationCounter){
						prec.next=curr.next;
						return;
					}
					prec=curr;
				}
			}
		}
	}
}
