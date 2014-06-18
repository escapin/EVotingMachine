package de.uni.trier.infsec.eVotingMachine.core;

import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.time.Timestamp;

import static de.uni.trier.infsec.utils.MessageTools.longToByteArray;
import static de.uni.trier.infsec.utils.MessageTools.concatenate;


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
	private final Signer signer;

	private int numberOfCandidates;
	private int[] votesForCandidates;
	private int operationCounter;


	public VotingMachine(int numberOfCandidates, Signer signer)
	{
		this.numberOfCandidates=numberOfCandidates;
		this.signer=signer;
		votesForCandidates = new int[numberOfCandidates];
		operationCounter=0;
	}

	public int collectBallot(int votersChoice) throws InvalidVote
	{
		if ( votersChoice < 0 || votersChoice >= numberOfCandidates ) 
			throw new InvalidVote();

		// increase the vote for the corresponding candidate
		votesForCandidates[votersChoice]++;

		return operationCounter++;
	}
	
	public void publishResult() throws NetworkError
	{
		signAndPost(Params.RESULTS, getResult(), signer);
	}


	///// PRIVATE //////
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

	}

	private byte[] getResult() {

		int[] _result = new int[numberOfCandidates];
		for (int i=0; i<numberOfCandidates; ++i) {
			int x = votesForCandidates[i];
			// CONSERVATIVE EXTENSION:
			// PROVE THAT THE FOLLOWING ASSINGMENT IS REDUNDANT
			x = Setup.correctResult[i];
			_result[i] = x;
		}
		return formatResult(_result);
	}

	private static byte[] formatResult(int[] _result) {
		String s = "Result of the election:\n";
		for( int i=0; i<_result.length; ++i ) {
			s += "  Number of votes for candidate " + i + ": " + _result[i] + "\n";
		}
		return s.getBytes();
	}

}
