package de.uni.trier.infsec.eVotingMachine.core;



import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
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
	
	
	//FIXME: ONLY FOR TESTING
	private static byte[] lastMessage=null;
	
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
		if ( voterChoice < 0 || voterChoice >= numberOfCandidates ) 
			throw new MalformedVote();
		
		
		// create a new inner ballot
		InnerBallot ballot=new InnerBallot();
		ballot.voterChoice=voterChoice;
		ballot.voteCounter=++voteCounter;
		ballot.timestamp=Utilities.getTimestamp();
		
		operationCounter++;
		
		byte[] entry=createAndSendEntry(operationCounter, Params.VOTE, ballot, bb_encryptor, signer);
		
		// add the the message (without the signature) to the log as an entry
		entryLog.add(copyOf(entry));
		
		// if the message was successfully sent to the bulletin board,
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
		
		byte[] entry=createAndSendEntry(operationCounter, Params.CANCEL, lastBallot, bb_encryptor, signer);
		
		// add the the message (without the signature) to the log as an entry
		entryLog.add(copyOf(entry));
		
		// if the message to delete the ballot was successfully sent 
		// to the bulletin board, we can decrease the vote 
		// for the corresponding candidate
		votesForCandidates[lastBallot.voterChoice]--;
		lastBallot=null;
	}
	
	/**
	 * 	Sign_VM [ RESULTS, timestamp, results ]
	 * @throws NetworkError
	 */
	public void publishResult() throws NetworkError
	{
		signAndSendPayload(Params.RESULTS, getResult(), signer);
	}
	
	/** 
	 * Sign_VM [ LOG, timestamp, concatenationEntry ]
	 * @throws NetworkError 
	 */
	public void publishLog() throws NetworkError
	{
		signAndSendPayload(Params.LOG, entryLog.getEntries(), signer);
	}
	
	
	
	/**
	 * Encrypt the inner_ballot with the tag, concatenate the operation counter, sign and send the message to the bullettin board.
	 * 
	 *   Sign_VM [ MACHINE_ENTRY, operationCounter, ENC_BB{ TAG, timestamp, voterChoice, voteCounter} ]
	 *   
	 *   Concatenation is made right to left
	 */
	private static byte[] createAndSendEntry(int operationCounter, byte[] tag, InnerBallot inner_ballot, Encryptor encryptor, Signer signer) throws NetworkError
	{
		byte[] vote_voteCounter = concatenate(	
							intToByteArray(inner_ballot.voterChoice),
							intToByteArray(inner_ballot.voteCounter));
		byte[] ballot = concatenate(
							longToByteArray(inner_ballot.timestamp),
							vote_voteCounter);
		byte[] tag_ballot= concatenate(tag, ballot);
		
		byte[] encrMsg = encryptor.encrypt(tag_ballot);
		
		byte[] opCounter_encryMsg = concatenate(		intToByteArray(operationCounter),
														encrMsg);
		
		byte[] entry = concatenate( Params.MACHINE_ENTRY, opCounter_encryMsg);
		
		//sign the entry
		byte[] signature = signer.sign(entry);
		byte[] msgToSend = concatenate(entry, signature);
		NetworkClient.send(msgToSend, Params.DEFAULT_HOST_BBOARD , Params.LISTEN_PORT_BBOARD);
		
		lastMessage=msgToSend; //FIXME: only for testing
		
		return entry;
	}
	
	/**
	 * Sign_VM [ TAG, timestamp, payload ]
	 * 
	 *   Concatenation is made right to left
	 */
	private static void signAndSendPayload(byte[] tag, byte[] payload, Signer signer) throws NetworkError 
	{
		long timestamp=Utilities.getTimestamp();
		byte[] timestamp_payload=concatenate(	longToByteArray(timestamp),
												payload);
		
		byte[] msgToSign = concatenate(tag, timestamp_payload);
		byte[] signature = signer.sign(msgToSign);
		
		byte[] msgToSend = concatenate(msgToSign, signature);
		
		NetworkClient.send(msgToSend, Params.DEFAULT_HOST_BBOARD , Params.LISTEN_PORT_BBOARD);
		
		lastMessage=msgToSend; //FIXME: only for testing
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
	
	
	//FIXME: ONLY FOR TESTING 
	public byte[] getLastSentMessage()
	{
		return lastMessage;
	}
	
}
