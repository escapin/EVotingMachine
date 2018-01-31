package eVotingMachine.core;

import static utils.MessageTools.concatenate;
import static utils.MessageTools.copyOf;
import static utils.MessageTools.intToByteArray;
import static utils.MessageTools.longToByteArray;

import funct.pkienc.Encryptor;
import funct.pkisig.Signer;
import lib.network.NetworkClient;
import lib.network.NetworkError;
import lib.time.Timestamp;

public class VotingMachine
{
	public class InnerBallot{
		public final int votersChoice;
		public final int voteCounter;
		public final long timestamp;
		public InnerBallot(int choice, int counter, long ts) {
			votersChoice = choice;
			voteCounter = counter;
			timestamp = ts;
		}
	}

	@SuppressWarnings("serial")
	public class InvalidVote extends Exception{}

	@SuppressWarnings("serial")
	public class InvalidCancelation extends Exception{}

	
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

	public int collectBallot(int votersChoice) throws InvalidVote
	{
		if ( votersChoice < 0 || votersChoice >= numberOfCandidates ) 
			throw new InvalidVote();

		// increase the vote for the corresponding candidate
		votesForCandidates[votersChoice]++;

		// create a new inner ballot
		lastBallot = new InnerBallot(votersChoice, ++voteCounter, Timestamp.get());

		// log, and send a new entry
		logAndSendNewEntry(Params.VOTE);
		
		return operationCounter;
	}

	public void cancelLastBallot() throws NetworkError, InvalidCancelation
	{
		if(lastBallot==null)
			throw new InvalidCancelation();
		votesForCandidates[lastBallot.votersChoice]--;
		logAndSendNewEntry(Params.CANCEL);
		lastBallot = null;
	}

	public void publishResult() throws NetworkError
	{
		signAndPost(Params.RESULTS, getResult(), signer);
	}

	public void publishLog() throws NetworkError
	{
		signAndPost(Params.LOG, entryLog.getEntries(), signer);
	}

	
	///// PRIVATE //////

	private void logAndSendNewEntry(byte[] tag) {
		// create a new (encrypted) log entry:
		byte[] entry = createEncryptedEntry(++operationCounter, tag, lastBallot, bb_encryptor, signer);	
		// add it to the log:
		entryLog.add(copyOf(entry));
		// and send this entry:
		try {
			signAndPost(Params.MACHINE_ENTRY, entry, signer);
		} catch (Exception ex) {}
			// this may cause an exception (NetworkError), but even if we do not get any exception, there is no guarantee 
			// that the entry was indeed delivered to the bulletin board, so we ignore problems
		
	}

	
	/**
	 * Create and return the new entry:
	 * 
	 *   ( operationCounter, ENC_BB{ TAG, timestamp, voterChoice, voteCounter} )
	 */
	private byte[] createEncryptedEntry(int operationCounter, byte[] tag, InnerBallot inner_ballot, Encryptor encryptor, Signer signer)
	{
		byte[] vote_voteCounter = concatenate(	
				intToByteArray(inner_ballot.votersChoice),
				intToByteArray(inner_ballot.voteCounter));
		byte[] ballot = concatenate(
				longToByteArray(inner_ballot.timestamp),
				vote_voteCounter);
		byte[] tag_ballot= concatenate(tag, ballot);
		byte[] encrMsg = encryptor.encrypt(tag_ballot);
		byte[] entry = concatenate( intToByteArray(operationCounter), encrMsg);
		return entry;
	}

	
	/**
	 * Sign_VM [ TAG, timestamp, message ]
	 * 
	 *   Concatenation is made right to left
	 */
	private static void signAndPost(byte[] tag, byte[] message, Signer signer) throws NetworkError 
	{		
		long timestamp = Timestamp.get();
		byte[] tag_timestamp = concatenate(tag, longToByteArray(timestamp));
		byte[] payload = concatenate(tag_timestamp, message);
		byte[] signature = signer.sign(payload);
		byte[] signedPayload = concatenate(payload, signature);
		NetworkClient.send(signedPayload, Params.DEFAULT_HOST_BBOARD, Params.LISTEN_PORT_BBOARD);

		lastMessage=signedPayload; //FIXME: only for testing
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
