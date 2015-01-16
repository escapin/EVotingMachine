package de.uni.trier.infsec.eVotingMachine.core;

import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.time.Timestamp;
import de.uni.trier.infsec.environment.Environment;

import de.uni.trier.infsec.utils.MessageTools;

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
	private final /*@ spec_public @*/ Encryptor bb_encryptor;
	private final /*@ spec_public @*/ Signer signer;

	private /*@ spec_public @*/ int numberOfCandidates;
	private /*@ spec_public @*/ int[] votesForCandidates;
	private int operationCounter;
	private /*@ spec_public @*/ int voteCounter;
	private /*@ spec_public @*/ EntryQueue entryLog;
	private /*@ spec_public nullable @*/ InnerBallot lastBallot;

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

	/*@ public behavior
	  @ requires votesForCandidates != null
	  @ 	&& votesForCandidates.length == numberOfCandidates
	  @ 	&& Params.VOTE != null && Params.MACHINE_ENTRY != null
	  @ 	&& Params.DEFAULT_HOST_BBOARD != null
	  @ 	&& bb_encryptor != null && signer != null && entryLog != null
	  @ 	&& votesForCandidates.length == numberOfCandidates;
	  @ diverges true;
	  @ assignable Environment.inputCounter, votesForCandidates[*], lastBallot, voteCounter;
	  @ ensures votesForCandidates.length == numberOfCandidates
	  @ 	&& lastBallot != null
	  @ 	&& voteCounter == \old(voteCounter) + 1
	  @ 	&& 0 <= votersChoice && votersChoice < numberOfCandidates
	  @ 	&& votersChoice == \old(votersChoice)
	  @ 	&& votersChoice == lastBallot.votersChoice
	  @ 	&& (votesForCandidates[votersChoice] == \old(votesForCandidates[votersChoice]) + 1)
	  @ 	&& (\forall int i; 0 <= i && i < numberOfCandidates && i != votersChoice;
	  @ 		votesForCandidates[i] == \old(votesForCandidates[i]))
	  @ 	&& \fresh(lastBallot) ; 
	  @*/
	public /*@ helper @*/ int collectBallot(int votersChoice) throws InvalidVote
	{
		/**
		 * JOANA edit: votersChoice is considered secret since it depends on the secret.
		 * If, depending on its value, an exception is thrown (or not), everything which happens
		 * after this if-statement depends on votersChoice, since votersChoice decides
		 * if everything is executed or the program crashes.
		 */
//		if ( votersChoice < 0 || votersChoice >= numberOfCandidates )
//			throw new InvalidVote();

		// increase the vote for the corresponding candidate
		/**
		 * JOANA edit: votersChoice is used as index here. Since JOANA does not reason
		 * about values and the boundaries of arrays, it assumes that the value of votersChoice
		 * decides whether the array access is successuful or the program crashes (and also whether
		 * the result is touched or not).
		 * Surrounding it with a try..catch-block makes the program in any case not crash, so,
		 * from JOANA's perspective, it is fine.
		 */
		try {votesForCandidates[votersChoice]++;} catch (Throwable t) {};

		// create a new inner ballot
		lastBallot = new InnerBallot(votersChoice, ++voteCounter, Timestamp.get());

		// log, and send a new entry
		logAndSendNewEntry(Params.VOTE);
		
		return operationCounter;
	}

	/*@ public behaviour
	  @ requires Params.CANCEL != null && Params.MACHINE_ENTRY != null
	  @ 	&& Params.DEFAULT_HOST_BBOARD != null && votesForCandidates != null
	  @ 	&& bb_encryptor != null && signer != null && entryLog != null
	  @ 	&& votesForCandidates.length == numberOfCandidates
	  @ 	&& (lastBallot != null ==>
	  @ 		(0 <= lastBallot.votersChoice && lastBallot.votersChoice < numberOfCandidates));
	  @ diverges true;
	  @ assignable votesForCandidates[*], lastBallot;
	  @ ensures votesForCandidates.length == numberOfCandidates
	  @ 	&& \old(lastBallot) != null && lastBallot == null
	  @ 	&& votesForCandidates[\old(lastBallot.votersChoice)]
	  @ 		== \old(votesForCandidates[\old(lastBallot.votersChoice)]) - 1
	  @ 	&& (\forall int i; 0 <= i && i < numberOfCandidates
	  @ 			&& i != \old(lastBallot.votersChoice);
	  @ 		votesForCandidates[i] == \old(votesForCandidates[i]));
	  @*/
	public /*@ helper @*/ void cancelLastBallot() throws InvalidCancelation
	{
		if(lastBallot==null)
			throw new InvalidCancelation();

		/**
		 * JOANA edit: votersChoice is used as index here. Since JOANA does not reason
		 * about values and the boundaries of arrays, it assumes that the value of votersChoice
		 * decides whether the array access is successuful or the program crashes (and also whether
		 * the result is touched or not).
		 * Surrounding it with a try..catch-block makes the program in any case not crash, so,
		 * from JOANA's perspective, it is fine.
		 */
		try {votesForCandidates[lastBallot.votersChoice]--;} catch (Throwable t) {};
		logAndSendNewEntry(Params.CANCEL);
		lastBallot = null;
	}

	/*@ public behaviour
	  @ requires Params.RESULTS != null && Params.DEFAULT_HOST_BBOARD != null
	  @ 	&& Setup.correctResult != null && votesForCandidates != null
	  @ 	&& bb_encryptor != null && signer != null && entryLog != null
	  @ 	&& numberOfCandidates == Setup.correctResult.length
	  @ 	&& votesForCandidates.length == numberOfCandidates
	  @ 	&& (\forall int j; 0 <= j && j < numberOfCandidates;
	  @ 		votesForCandidates[j] == Setup.correctResult[j]);
	  @ diverges true;
	  @ assignable Environment.inputCounter, Environment.result;
	  @ ensures votesForCandidates.length == numberOfCandidates;
	  @*/
	public /*@ helper @*/ void publishResult() throws NetworkError
	{
		signAndPost(Params.RESULTS, getResult(), signer);
	}

	/*@ public behavior
	  @ requires Params.LOG != null && Params.DEFAULT_HOST_BBOARD != null
	  @ 	&& votesForCandidates != null && bb_encryptor != null
	  @ 	&& signer != null && entryLog != null
	  @ 	&& votesForCandidates.length == numberOfCandidates;
	  @ assignable Environment.inputCounter, Environment.result;
	  @ diverges true;
	  @ ensures votesForCandidates.length == numberOfCandidates;
	  @*/
	public /*@ helper @*/ void publishLog() throws NetworkError
	{
		signAndPost(Params.LOG, entryLog.getEntries(), signer);
	}


	///// PRIVATE //////

	/*@ private behaviour
	  @ requires Params.MACHINE_ENTRY != null && Params.DEFAULT_HOST_BBOARD != null
	  @ 	&& bb_encryptor != null && signer != null && entryLog != null
	  @ 	&& votesForCandidates != null
	  @ 	&& votesForCandidates.length == numberOfCandidates;
	  @ requires tag != null;
	  @ diverges true;
	  @ ensures true;
	  @*/
	private /*@ strictly_pure helper @// to be proven with JOANA */ void logAndSendNewEntry(/*@ nullable @*/ byte[] tag) {
		// create a new (encrypted) log entry:
		byte[] entry = createEncryptedEntry(++operationCounter, tag, lastBallot, bb_encryptor, signer);	
		// add it to the log:
		entryLog.add(MessageTools.copyOf(entry));
		// and send this entry:
		try {
			signAndPost(Params.MACHINE_ENTRY, entry, signer);
		} catch (Exception ex) {}
		// this may cause an exception (NetworkError), but even if we do not get any exception,
		// there is no guarantee that the entry was indeed delivered to the bulletin board,
		// so we ignore problems
	}

	/**
	 * Create and return the new entry:
	 *
	 *   ( operationCounter, ENC_BB{ TAG, timestamp, voterChoice, voteCounter} )
	 */
	private /*@ pure helper @*/ byte[] createEncryptedEntry(int operationCounter, byte[] tag,
															InnerBallot inner_ballot,
															Encryptor encryptor, Signer signer)
	{
		byte[] vote_voteCounter = MessageTools.concatenate(
		                MessageTools.intToByteArray(inner_ballot.votersChoice),
		                MessageTools.intToByteArray(inner_ballot.voteCounter));
		byte[] ballot = MessageTools.concatenate(
		                    MessageTools.longToByteArray(inner_ballot.timestamp),
		                    vote_voteCounter);
		byte[] tag_ballot= MessageTools.concatenate(tag, ballot);
		byte[] encrMsg = encryptor.encrypt(tag_ballot);
		byte[] entry = MessageTools.concatenate( MessageTools.intToByteArray(operationCounter), encrMsg);
		return entry;
	}

	/**
	 * Sign_VM [ TAG, timestamp, message ]
	 * 
	 *   Concatenation is made right to left
	 */
	/*@ private behaviour
	  @ requires Params.DEFAULT_HOST_BBOARD != null;
	  @ assignable Environment.inputCounter, Environment.result;
	  @ diverges true;
	  @ ensures true;
	  @*/
	private static /*@ helper @*/ void signAndPost(byte[] tag, /*@ nullable @*/ byte[] message, Signer signer)
			throws NetworkError
	{
		long timestamp = Timestamp.get();
		byte[] tag_timestamp = MessageTools.concatenate(tag, MessageTools.longToByteArray(timestamp));
		byte[] payload = MessageTools.concatenate(tag_timestamp, message);
		byte[] signature = signer.sign(payload);
		byte[] signedPayload = MessageTools.concatenate(payload, signature);
		NetworkClient.send(signedPayload, Params.DEFAULT_HOST_BBOARD, Params.LISTEN_PORT_BBOARD);

	}

	/*@ private behaviour
	  @ requires Setup.correctResult != null
	  @ 	&& votesForCandidates != null
	  @ 	&& bb_encryptor != null && signer != null && entryLog != null
	  @ 	&& numberOfCandidates == Setup.correctResult.length
	  @ 	&& numberOfCandidates == votesForCandidates.length
	  @ 	&& (\forall int j; 0 <= j && j < numberOfCandidates;
	  @ 		votesForCandidates[j] == Setup.correctResult[j]);
	  @ diverges numberOfCandidates < 0;
	  @ signals_only NegativeArraySizeException;
	  @ signals (NegativeArraySizeException e) numberOfCandidates < 0;
	  @*/
	private /*@ pure helper @*/ byte[] getResult() {

		int[] _result = new int[numberOfCandidates];
		/*@ loop_invariant 0 <= i && i <= votesForCandidates.length
		  @ 		&& 0 <= numberOfCandidates
		  @ 		&& _result != null && \fresh(_result)
		  @ 		&& _result.length == numberOfCandidates
		  @ 		&& i <= Setup.correctResult.length
		  @ 		&& i <= _result.length
		  @ 		&& i <= numberOfCandidates;
		  @ assignable _result[*];
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
	private static /*@ pure helper @// not provable */ byte[] formatResult(int[] _result) {
		String s = "Result of the election:\n";
		for( int i=0; i<_result.length; ++i ) {
			s += "  Number of votes for candidate " + i + ": " + _result[i] + "\n";
		}
		return s.getBytes();
	}
}