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
	public class InnerBallot{
		public int voterChoice;
		public int voteCounter;
		public long timestamp;
	}
	
	@SuppressWarnings("serial")
	public class MalformedVote extends Exception{}
	
	// CRYPTOGRAPHIC FUNCTIONALITIES
	private final Encryptor bb_encryptor;
	private final Signer signer;
	
	private int numberOfCandidates;
	private int[] votesForCandidates;
	private int operationCounter, voteCounter;
	private EntryQueue entryLog;
	private InnerBallot lastBallot;
	
	
	public VotingMachine(int numberOfCandidates, Encryptor bb_encryptor, Signer signer)
	{
		this.numberOfCandidates=numberOfCandidates;
		this.bb_encryptor=bb_encryptor;
		this.signer=signer;
		votesForCandidates = new int[numberOfCandidates];
		entryLog = new EntryQueue();
		operationCounter=0;
		voteCounter=0;
		lastBallot=null;
	}
	
	public int collectBallot(int voterChoice) throws NetworkError, MalformedVote
	{
		if (voterChoice < 0 || voterChoice >= numberOfCandidates ) 
			throw new MalformedVote();
		
		
		// create a new inner ballot
		InnerBallot ballot=new InnerBallot();
		ballot.voterChoice=voterChoice;
		ballot.voteCounter=++voteCounter;
		ballot.timestamp=Utilities.getTimestamp();
		
		operationCounter++;
		
		createAndSendEntry(operationCounter, Params.VOTE, ballot);
		
		// if the message was successfully sent to the bullettin board,
		// we can increase the vote for the corresponding candidate
		votesForCandidates[voterChoice]++;
		lastBallot=ballot;
		
		return operationCounter;
	}
	
	public void cancelLastBallot() throws NetworkError
	{
		if(lastBallot==null)
			return;
		operationCounter++;
		
		createAndSendEntry(operationCounter, Params.CANCEL, lastBallot);
		
		// if the message to delete the ballot was successfully sent 
		// to the bullettin board, we can decrease the vote 
		// for the corresponding candidate
		votesForCandidates[lastBallot.voterChoice]--;
		lastBallot=null;
	}
	
	
	/**
	 * Encrypt the inner_ballot with the tag, concatenate the operation counter, sign and send the message to the bullettin board.
	 * 
	 *   Sign_VM [ operationCounter, ENC_BB{ TAG, timestamp, voterChoice, voteCounter} ]
	 *   
	 *   Concatenation is made right to left
	 */
	private void createAndSendEntry(int operationCounter, byte[] tag, InnerBallot inner_ballot) throws NetworkError{
		byte[] vote_voteCounter = concatenate(	
							intToByteArray(inner_ballot.voterChoice),
							intToByteArray(inner_ballot.voteCounter));
		byte[] ballot = concatenate(
							longToByteArray(inner_ballot.timestamp),
							vote_voteCounter);
		byte[] tag_ballot= concatenate(tag, ballot);
		
		byte[] encrMsg = bb_encryptor.encrypt(tag_ballot);
		
		byte[] entry = concatenate(		intToByteArray(operationCounter),
										encrMsg);
		
		// add the ballot to the log as an entry
		entryLog.add(copyOf(entry));
		
		//sign the entry
		byte[] signature = signer.sign(entry);
		byte[] msgToSend = concatenate(entry, signature);
		NetworkClient.send(msgToSend, Params.DEFAULT_HOST_BBOARD , Params.LISTEN_PORT_BBOARD);
	}
	
	
	
	/**
	 * 	Sign_VM [ timestamp, results ]
	 * @throws NetworkError
	 */
	public void publishResult() throws NetworkError
	{
		signAndSendPayload(getResult());
	}
	
	/** 
	 * Sign_VM [ timestamp, concatenationEntry ]
	 * @throws NetworkError 
	 */
	public void publishLog() throws NetworkError
	{
		signAndSendPayload(entryLog.getEntries());
	}
	
	private void signAndSendPayload(byte[] payload) throws NetworkError 
	{
		long timestamp=Utilities.getTimestamp();
		byte[] msgToSign=concatenate(	longToByteArray(timestamp),
										payload);
		
		byte[] signature = signer.sign(msgToSign);
		
		byte[] msgToSend = concatenate(msgToSign, signature);
		
		NetworkClient.send(msgToSend, Params.DEFAULT_HOST_BBOARD , Params.LISTEN_PORT_BBOARD);
	}
	
	private byte[] getResult() {
		
		int[] _result = new int[numberOfCandidates];
        for (int i=0; i<numberOfCandidates; ++i) {
            int x = votesForCandidates[i];
            // CONSERVATIVE EXTENSION:
            // PROVE THAT THE FOLLOWING ASSINGMENT IS REDUNDANT
            // x = consExt(i);
            _result[i] = x;
        }
        return formatResult(_result);
	}
	
	//FIXME: to be done
//    private int consExt(int i) {
//    	return Setup.correctResult[i];
//    }

	private static byte[] formatResult(int[] _result) {
		String s = "Result of the election:\n";
		for( int i=0; i<_result.length; ++i ) {
			s += "  Number of votes for candidate " + i + ": " + _result[i] + "\n";
		}
		return s.getBytes();
	}
	
	
	
	/**
	 * List of labels.
	 * For each 'label' maintains an counter representing 
	 * how many times the label has been used.
	 */
	static private class EntryQueue {

		static class Node 
		{
			public byte[] entry;
			public Node next;

			public Node(byte[] entry) 
			{
				this.entry = entry;
				this.next=null;
			}
		}

		private Node head, last = null;

		public void add(byte[] entry) 
		{
			Node newEntry=new Node(entry);
			if(head==null)
				head=last=newEntry;
			else {
				last.next=newEntry;
				last=newEntry;
			}
		}
		
		public byte[] getEntries()
		{
			if(head==null) 
				return new byte[]{};
			byte[] entries=head.entry;
			for(Node n=head.next; n!=null; n=n.next)
				entries=concatenate(entries, n.entry);
			return entries;
		}
		
		
	}
}
