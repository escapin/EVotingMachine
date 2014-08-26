package de.uni.trier.infsec.eVotingMachine.core;

import de.uni.trier.infsec.eVotingMachine.core.VotingMachine.InvalidCancelation;
import de.uni.trier.infsec.eVotingMachine.core.VotingMachine.InvalidVote;
import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.functionalities.pkienc.RegisterEnc;
import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkienc.Decryptor;
import de.uni.trier.infsec.functionalities.pkisig.RegisterSig;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.functionalities.pkisig.Verifier;
import de.uni.trier.infsec.lib.network.NetworkError;

public final class Setup 
{

	// the correct result
	static int[] correctResult; // CONSERVATIVE EXTENSION

	//@ private static ghost boolean flag;

	/*@ private behaviour
	  @ requires 0 < numberOfCandidates
	  @            && Environment.inputValues != null && 0 <= Environment.inputCounter;
	  @ diverges true;
	  @ signals_only ArrayIndexOutOfBoundsException, NegativeArraySizeException;
	  @ assignable Environment.inputCounter;
	  @ ensures 0 <= numberOfVoters && \result.length == numberOfVoters
	  @            && Environment.inputValues != null && 0 <= Environment.inputCounter
	  @            && (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 			0 <= \result[j] && \result[j] < numberOfCandidates)
	  @            && (\forall Object o; o != \result; !\fresh(o));
	  @ signals (Exception e) Environment.inputValues != null && 0 <= Environment.inputCounter;
	  @*/
	private static /*@ helper @*/ int[] createChoices(int numberOfVoters,
	                                                  int numberOfCandidates) {
		final int[] choices = new int[numberOfVoters];
		/*@ loop_invariant 0 <= i && i <= numberOfVoters && choices != null
		  @ 			&& choices.length == numberOfVoters
		  @ 			&& Environment.inputValues != null
		  @ 			&& 0 <= numberOfVoters
		  @ 			&& 0 < numberOfCandidates
		  @ 			&& 0 <= Environment.inputCounter
		  @ 			&& (\forall int j; 0 <= j && j < i;
		  @ 					0 <= choices[j] && choices[j] < numberOfCandidates)
		  @                     && (\forall Object o; o != choices; !\fresh(o));
		  @ assignable Environment.inputCounter, choices[*];
		  @ decreases numberOfVoters - i;
		  @*/
		for (int i=0; i<numberOfVoters; ++i) {
			choices[i] = Environment.untrustedInput(numberOfCandidates);
		}
		return choices;
	}

	/*@ private normal_behaviour
	  @ requires 0 < numberOfCandidates
	  @ 		&& (\forall int j; 0 <= j && j < choices.length;
	  @ 			0 <= choices[j] && choices[j] < numberOfCandidates);
	  @ ensures \result.length == numberOfCandidates
	  @            && (\forall int j; 0 <= j && j < numberOfCandidates;
	  @                    \result[j] == (\num_of int k; 0 <= k && k < choices.length; choices[k] == j))
	  @            && (\forall Object o; o != \result; !\fresh(o));
	  @*/
	private static /*@ pure helper @*/ int[] computeResult (int[] choices,
	                                                        int numberOfCandidates) {
		int[] res = new int[numberOfCandidates];
		/*@ loop_invariant 0 <= i && i <= choices.length && res.length == numberOfCandidates
		  @ 			&& (\forall int j; 0 <= j && j < i;
		  @ 				0 <= choices[j] && choices[j] < numberOfCandidates)
		  @                   && (\forall int j; 0 <= j && j < numberOfCandidates;
		  @                             res[j] ==
		  @                     (\num_of int k; 0 <= k && k < i; choices[k] == j))
		  @                   && (\forall Object o; o != res; !\fresh(o));
		  @ assignable res[*];
		  @ decreases choices.length - i;
		  @*/
		for (int i=0; i<choices.length; i++)
			++res[choices[i]];
		return res;
	}

	/*@ private normal_behaviour
	  @ requires r1.length == r2.length;
	  @ ensures \result == (\forall int i; 0 <= i && i < r1.length; r1[i] == r2[i]);
	  @*/
	private static /*@ strictly_pure helper @*/ boolean equalResult(int[] r1, int[] r2) {
		/*@ loop_invariant 0 <= j && r1.length == r2.length
		  @ 			&&  (\forall int i; 0 <= i && i < j; r1[i] == r2[i]);
		  @ assignable \strictly_nothing;
		  @ decreases r1.length - j;
		  @*/
		for (int j= 0; j<r1.length; j++)
			if (r1[j]!=r2[j]) return false;
		return true;
	}

	public static void main (String[] a) throws Throwable {

		// CREATING THE CRYPTOGRAPHIC FUNCTIONALITIES AND MAIN COMPONENTS OF THE SYSTEM

		// Determine the number of candidates and the number of voters:
		int numberOfCandidates = Environment.untrustedInput();
		int numberOfVoters = Environment.untrustedInput();
		if (numberOfVoters<=0 || numberOfCandidates<=0)
			throw new Throwable();	// abort

		// Create and register decryptor/encryptor of auditors:
		Decryptor audit_decryptor = new Decryptor();
		Encryptor audit_encryptor = audit_decryptor.getEncryptor();
		RegisterEnc.registerEncryptor(audit_encryptor, Params.AUDITORS_ID, Params.ENC_DOMAIN);

		// Create and register signer/verifier of the voting machine
		Signer vm_signer = new Signer();
		Verifier vm_verifier = vm_signer.getVerifier();
		RegisterSig.registerVerifier(vm_verifier, Params.VOTING_MACHINE_ID, Params.SIG_DOMAIN);

		// Create the voting machine and the bulletin board:
		VotingMachine vm = new VotingMachine(numberOfCandidates, audit_encryptor, vm_signer);
		BulletinBoard bb = new BulletinBoard(vm_verifier);

		boolean secret = a.length > 0;
		main2(vm, bb, numberOfCandidates, numberOfVoters, secret);

	}

	/*@ behaviour
	  @ requires 0 < numberOfCandidates
	  @             && Environment.inputValues != null && 0 <= Environment.inputCounter
	  @             && Params.VOTE != null && Params.CANCEL != null && Params.MACHINE_ENTRY != null
	  @             && Params.DEFAULT_HOST_BBOARD != null
	  @ 			&& vm.votesForCandidates != null;
	  @ diverges true;
	  @ signals_only ArrayIndexOutOfBoundsException, NegativeArraySizeException, Throwable,
	  @                    NetworkError, Error, InvalidCancelation, InvalidVote;
	  @ assignable correctResult, Environment.inputCounter, Environment.result,
	  @ 			vm.voteCounter, vm.votesForCandidates[*];
	  @ ensures flag;
	  @ signals (Throwable e) true;
	  @*/
	private static /*@ helper @*/ void main2(VotingMachine vm, BulletinBoard bb,
	                                         int numberOfCandidates,
	                                         int numberOfVoters, boolean secret)
			throws Throwable, InvalidVote, NetworkError, InvalidCancelation {
		// let the environment determine two vectors of choices
		int[] choices0 = createChoices(numberOfVoters, numberOfCandidates);
		int[] choices1 = createChoices(numberOfVoters, numberOfCandidates);

		// check that those vectors give the same result
		int[] r0 = computeResult(choices0, numberOfCandidates);
		int[] r1 = computeResult(choices1, numberOfCandidates);
		if (!equalResult(r0,r1))
			throw new Throwable();	// abort if the vectors do not yield the same result

		// store correct result (CONSERVATIVE EXTENSTION)
		correctResult = r1;

		// THE MAIN LOOP
		mainLoop(vm, bb, numberOfVoters, secret, choices0, choices1);
	}

	/*@ private behaviour
	  @ requires correctResult != null && 0 < correctResult.length
	  @ 		&& Environment.inputValues != null && 0 <= Environment.inputCounter
	  @ 		&& choices0.length == numberOfVoters
	  @ 		&& choices0.length == choices1.length
	  @ 		&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 			0 <= choices0[j] && choices0[j] < correctResult.length)
	  @ 		&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 			0 <= choices1[j] && choices1[j] < correctResult.length)
	  @             && (\forall int j; 0 <= j && j < correctResult.length;
	  @                    correctResult[j] ==
	  @                            (\num_of int k; 0 <= k && k < numberOfVoters; choices0[k] == j))
	  @             && (\forall int j; 0 <= j && j < correctResult.length;
	  @                    correctResult[j] ==
	  @                            (\num_of int k; 0 <= k && k < numberOfVoters; choices1[k] == j))
	  @ 		&& Params.VOTE != null && Params.CANCEL != null && Params.MACHINE_ENTRY != null
	  @ 		&& Params.DEFAULT_HOST_BBOARD != null
	  @ 		&& vm.votesForCandidates != null;
	  @ diverges true;
	  @ signals_only ArrayIndexOutOfBoundsException, NegativeArraySizeException, NetworkError,
	  @                    Error, InvalidCancelation, InvalidVote;
	  @ assignable Environment.inputCounter, Environment.result,
	  @ 			vm.voteCounter, vm.votesForCandidates[*];
	  @ ensures flag;
	  @ signals (Throwable e) true;
	  @*/
	private static /*@ helper @*/ void mainLoop(VotingMachine vm, BulletinBoard bb,
	                                            int numberOfVoters, boolean secret,
	                                            int[] choices0, int[] choices1)
			throws Throwable, InvalidVote, NetworkError, InvalidCancelation {
		final int N = Environment.untrustedInput(); // the environment decides how long the system runs
		final int[] actions = Environment.untrustedInputArray(N);
		final int[] audit_choices = Environment.untrustedInputArray(N);
		byte[][] requests = Environment.untrustedInputMessages(N);
		innerMain(vm, bb, numberOfVoters, secret, choices0, choices1,
		          N, actions, audit_choices, requests);
	}

	/*@ private behaviour
	  @ requires correctResult != null && 0 < correctResult.length
	  @ 		&& Environment.inputValues != null && 0 <= Environment.inputCounter
	  @ 		&& choices0.length == numberOfVoters
	  @ 		&& choices0.length == choices1.length
	  @ 		&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 				0 <= choices0[j] && choices0[j] < correctResult.length)
	  @ 		&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 				0 <= choices1[j] && choices1[j] < correctResult.length)
	  @ 		&& (\forall int j; 0 <= j && j < correctResult.length;
	  @ 				correctResult[j] ==
	  @ 					(\num_of int k; 0 <= k && k < numberOfVoters; choices0[k] == j))
	  @ 		&& (\forall int j; 0 <= j && j < correctResult.length;
	  @ 				correctResult[j] ==
	  @ 					(\num_of int k; 0 <= k && k < numberOfVoters; choices1[k] == j))
	  @ 		&& Params.VOTE != null && Params.CANCEL != null && Params.MACHINE_ENTRY != null
	  @ 		&& Params.DEFAULT_HOST_BBOARD != null
	  @ 		&& vm.votesForCandidates != null;
	  @ diverges true;
	  @ signals_only ArrayIndexOutOfBoundsException, NegativeArraySizeException, NetworkError,
	  @ 				Error, InvalidCancelation, InvalidVote;
	  @ assignable Environment.inputCounter, Environment.result,
	  @ 			vm.voteCounter, vm.votesForCandidates[*];
	  @ ensures flag;
	  @ signals (Throwable e) true;
	  @*/
	private static /*@ helper @*/ void innerMain(VotingMachine vm, BulletinBoard bb,
	                                             int numberOfVoters, boolean secret, int[] choices0,
	                                             int[] choices1, final int N, final int[] actions,
	                                             final int[] audit_choices, byte[][] requests)
	                throws InvalidVote, NetworkError, InvalidCancelation {
		int voterNr = 0;
		/*@ loop_invariant 0 <= i
		  @ 			&& 0 <= voterNr && voterNr < i
		  @ 			&& voterNr <= numberOfVoters
		  @ 			&& (\forall int j; 0 <= j && j < voterNr;
		  @ 				vm.votesForCandidates[j] ==
		  @ 					(\num_of int k; 0 <= k && k < j; choices0[k] == choices0[j]));
		  @ assignable Environment.inputCounter, Environment.result,
		  @ 			vm.voteCounter, vm.votesForCandidates[*];
		  @ decreases N - i;
		  @*/
		for( int i=0; i<N; ++i ) {
			// TODO: change to if
			switch( actions[i] ) {

			case 0: // next voter votes
				if (voterNr<numberOfVoters) {
					int choice = secret ? choices0[voterNr] : choices1[voterNr];
					vm.collectBallot(choice);
					++voterNr;
				}
				break;

			case 1: // make the voting machine publish the current (encrypted) log
				vm.publishLog();
				break;

			case 2: // audit (this step altogether should not change the result)
				int audit_choice = audit_choices[i];
				/*@ private behaviour
				  @ diverges true;
				  @ assignable Environment.inputCounter, Environment.result, vm.lastBallot;
				  @ signals_only InvalidVote, ArrayIndexOutOfBoundsException, Error,
				  @ 			 NetworkError, InvalidCancelation;
				  @ ensures vm.lastBallot == null;
				  @ signals (Throwable e) true;
				  @*/
				{
					int sqnumber = vm.collectBallot(audit_choice);
					Environment.untrustedOutput(sqnumber);
					vm.publishLog();
					vm.cancelLastBallot();
				}
				break;

			case 3: // deliver a message to the bulletin board
				byte[] request = requests[i];
				bb.onPost(request);
				break;

			case 4: // make the bulletin board send its content over the network
				bb.onRequestContent();
				break;
			}
		}

		// make the voting machine publish the result (only if all the voters has voted):
		if (voterNr == numberOfVoters)
			vm.publishResult();
		//@ set flag = true;
		{}
	}
}