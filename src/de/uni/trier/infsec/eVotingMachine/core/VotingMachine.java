package de.uni.trier.infsec.eVotingMachine.core;

import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.time.Timestamp;

import static de.uni.trier.infsec.utils.MessageTools.intToByteArray;
import static de.uni.trier.infsec.utils.MessageTools.longToByteArray;
import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.copyOf;

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

	public class InvalidVote extends Exception{}

	public class InvalidCancelation extends Exception{}

	
	// CRYPTOGRAPHIC FUNCTIONALITIES
	private final Encryptor bb_encryptor;
	private final Signer signer;

	private /*@ spec_public @*/ int numberOfCandidates;
	private /*@ spec_public @*/ int[] votesForCandidates;
	private int operationCounter;
	private /*@ spec_public @*/ int voteCounter;
	private EntryQueue entryLog;
	private /*@ spec_public @*/ InnerBallot lastBallot;

	//@ public instance invariant votesForCandidates.length == numberOfCandidates;


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

	// ensures \only_assigned(votesForCandidates[*], lastBallot); // TODO implement
	/*@ public behaviour
	  @ requires \invariant_for(this);
	  @ diverges votersChoice < 0 || votersChoice >= numberOfCandidates;
	  @ assignable votesForCandidates[*], lastBallot, voteCounter;
	  @ signals_only InvalidVote;
	  @ ensures \invariant_for(this) && lastBallot != null
	  @ 	&& 0 <= votersChoice && votersChoice < numberOfCandidates
	  @ 	&& votesForCandidates[votersChoice] == \old(votesForCandidates[votersChoice]) + 1;
	  @ signals (InvalidVote e) votersChoice < 0 || votersChoice >= numberOfCandidates;
	  @*/
	public /*@ helper @*/ int collectBallot(int votersChoice) throws InvalidVote
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

	/*@ public behaviour
	  @ assignable votesForCandidates[*], lastBallot;
	  @ ensures \invariant_for(this) && lastBallot == null
	  @ 	&& votesForCandidates[lastBallot.votersChoice]
	  @ 		== \old(votesForCandidates[lastBallot.votersChoice]) - 1;
	  @ signals (InvalidCancelation e) \old(lastBallot) == null && lastBallot == null;
	  @*/
	public void cancelLastBallot() throws InvalidCancelation
	{
		if(lastBallot==null)
			throw new InvalidCancelation();
		votesForCandidates[lastBallot.votersChoice]--;
		logAndSendNewEntry(Params.CANCEL);
		lastBallot = null;
	}

	/*@ public behaviour
	  @ ensures true;
	  @*/
	public void publishResult() throws NetworkError
	{
		signAndPost(Params.RESULTS, getResult(), signer);
	}

	/*@ public behaviour
	  @ ensures true;
	  @*/
	public /*@ strictly_pure @// to be proven with JOANA */ void publishLog() throws NetworkError
	{
		signAndPost(Params.LOG, entryLog.getEntries(), signer);
	}


	///// PRIVATE //////

	/*@ private normal_behaviour
	  @ ensures true;
	  @*/
	private /*@ strictly_pure @// to be proven with JOANA */ void logAndSendNewEntry(byte[] tag) {
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
	 *@ private behaviour
	  @ signals_only NetworkError;
	  @ ensures true;
	  @ signals (NetworkError e) true;
	  @*/
	private static /*@ strictly_pure helper @*/ void signAndPost(byte[] tag, byte[] message, Signer signer)
			throws NetworkError
	{		
		long timestamp = Timestamp.get();
		byte[] tag_timestamp = concatenate(tag, longToByteArray(timestamp));
		byte[] payload = concatenate(tag_timestamp, message);
		byte[] signature = signer.sign(payload);
		byte[] signedPayload = concatenate(payload, signature);
		NetworkClient.send(signedPayload, Params.DEFAULT_HOST_BBOARD, Params.LISTEN_PORT_BBOARD);

	}

	/*@ private behaviour
	  @ requires Setup.correctResult != null
	  @ 		&& numberOfCandidates <= Setup.correctResult.length
	  @ 		&& numberOfCandidates <= votesForCandidates.length
	  @ 		&& (\forall int j; 0 <= j && j < numberOfCandidates;
	  @ 				votesForCandidates[j] == Setup.correctResult[j]);
	  @ diverges numberOfCandidates < 0;
	  @ signals_only NegativeArraySizeException;
	  @ signals (NegativeArraySizeException e) numberOfCandidates < 0;
	  @*/
	private /*@ strictly_pure @*/ byte[] getResult() {

		int[] _result = new int[numberOfCandidates];
		/*@ loop_invariant 0 <= i && i < votesForCandidates.length
		  @ 			&& i < Setup.correctResult.length
		  @ 			&& i < _result.length
		  @ 			&& i < numberOfCandidates;
		  @ assignable \strictly_nothing;
		  @ decreases numberOfCandidates -i;
		  @*/
		for (int i=0; i<numberOfCandidates; ++i) {
			int x = votesForCandidates[i];
			// CONSERVATIVE EXTENSION:
			// PROVE THAT THE FOLLOWING ASSINGMENT IS REDUNDANT
			/*@ public normal_behaviour
			  @ requires 0 <= i && i < Setup.correctResult.length;
			  @ assignable x;
			  @ ensures x == \old(x);
			  @*/
			{ x = Setup.correctResult[i]; }
			_result[i] = x;
		}
		return formatResult(_result);
	}

	/*@ private normal_behaviour
	  @ requires true;
	  @*/
	private static /*@ strictly_pure @*/ byte[] formatResult(int[] _result) {
		String s = "Result of the election:\n";
		for( int i=0; i<_result.length; ++i ) {
			s += "  Number of votes for candidate " + i + ": " + _result[i] + "\n";
		}
		return s.getBytes();
	}
}