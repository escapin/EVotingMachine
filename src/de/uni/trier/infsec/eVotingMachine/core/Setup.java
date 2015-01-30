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

	/*@ private behavior
	  @ requires 0 < numberOfCandidates;
	  @ diverges true;
	  @ assignable Environment.inputCounter;
	  @ ensures 0 <= numberOfVoters && \result.length == numberOfVoters
	  @ 	&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 		0 <= \result[j] && \result[j] < numberOfCandidates)
	  @ 	&& \fresh(\result);
	  @*/
	private static /*@ helper @*/ int[] createChoices(int numberOfVoters,
	                                                  int numberOfCandidates) {
		final int[] choices = new int[numberOfVoters];
		/*@ loop_invariant 0 <= i && i <= numberOfVoters && choices != null
		  @ 		&& choices.length == numberOfVoters
		  @ 		&& 0 <= numberOfVoters && 0 < numberOfCandidates
		  @ 		&& (\forall int j; 0 <= j && j < i;
		  @ 			0 <= choices[j] && choices[j] < numberOfCandidates)
		  @ 		&& \fresh(choices);
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
	  @ 	&& (\forall int j; 0 <= j && j < choices.length;
	  @ 		0 <= choices[j] && choices[j] < numberOfCandidates);
	  @ ensures \result.length == numberOfCandidates
	  @ 	&& \fresh(\result) && choices != \result
	  @ 	&& (\forall int j; 0 <= j && j < numberOfCandidates;
	  @ 		\result[j] == (\num_of int k; 0 <= k && k < choices.length; choices[k] == j))
	  @ 	&& (\forall Object o; o != \result; !\fresh(o));
	  @*/
	private static /*@ pure helper @*/ int[] computeResult (int[] choices,
	                                                        int numberOfCandidates) {
		int[] res = new int[numberOfCandidates];
		/*@ loop_invariant 0 <= i && i <= choices.length && res.length == numberOfCandidates
		  @ 		&& (\forall int j; 0 <= j && j < i;
		  @ 			0 <= choices[j] && choices[j] < numberOfCandidates)
		  @ 		&& (\forall int j; 0 <= j && j < numberOfCandidates;
		  @ 			res[j] ==
		  @ 				(\num_of int k; 0 <= k && k < i; choices[k] == j))
		  @ 		&& \fresh(res)
		  @ 		&& (\forall Object o; o != res; !\fresh(o));
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
		  @ 		&&  (\forall int i; 0 <= i && i < j; r1[i] == r2[i]);
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

	/*@ private behaviour
	  @ requires 0 < numberOfCandidates
	  @ 	&& Params.VOTE != null && Params.CANCEL != null && Params.MACHINE_ENTRY != null
	  @ 	&& Params.DEFAULT_HOST_BBOARD != null && Params.RESULTS != null && Params.LOG != null
	  @ 	&& vm.votesForCandidates != null && vm.numberOfCandidates == numberOfCandidates
	  @ 	&& vm.votesForCandidates.length == numberOfCandidates
	  @ 	&& vm.bb_encryptor != null && vm.signer != null && vm.entryLog != null
	  @ 	&& bb.verifier != null && bb.entryLog != null
	  @ 	&& (\forall int j; 0 <= j && j < vm.numberOfCandidates;
	  @ 		vm.votesForCandidates[j] == 0);
	  @ diverges true;
	  @ assignable correctResult, Environment.inputCounter, Environment.result, vm.lastBallot,
	  @ 		vm.voteCounter, vm.votesForCandidates[*], flag;
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
	  @ 	&& vm.votesForCandidates != null && correctResult != vm.votesForCandidates
	  @ 	&& correctResult != choices0 && correctResult != choices1
	  @ 	&& vm.votesForCandidates != choices0 && vm.votesForCandidates != choices1
	  @ 	&& vm.bb_encryptor != null && vm.signer != null && vm.entryLog != null
	  @ 	&& bb.verifier != null && bb.entryLog != null
	  @ 	&& vm.votesForCandidates.length == vm.numberOfCandidates
	  @ 	&& Params.VOTE != null && Params.CANCEL != null && Params.MACHINE_ENTRY != null
	  @ 	&& Params.DEFAULT_HOST_BBOARD != null && Params.RESULTS != null && Params.LOG != null
	  @ 	&& vm.votesForCandidates.length == correctResult.length
	  @ 	&& choices0.length == numberOfVoters
	  @ 	&& choices0.length == choices1.length
	  @ 	&& (\forall int j; 0 <= j && j < vm.numberOfCandidates;
	  @ 		vm.votesForCandidates[j] == 0)
	  @ 	&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 		0 <= choices0[j] && choices0[j] < correctResult.length)
	  @ 	&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 		0 <= choices1[j] && choices1[j] < correctResult.length)
	  @ 	&& (\forall int j; 0 <= j && j < correctResult.length;
	  @ 		correctResult[j] ==
	  @ 			(\num_of int k; 0 <= k && k < numberOfVoters; choices0[k] == j))
	  @ 	&& (\forall int j; 0 <= j && j < correctResult.length;
	  @ 		correctResult[j] ==
	  @ 			(\num_of int k; 0 <= k && k < numberOfVoters; choices1[k] == j));
	  @ diverges true;
	  @ assignable Environment.inputCounter, Environment.result, vm.lastBallot,
	  @ 		vm.voteCounter, vm.votesForCandidates[*], flag;
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
	  @ 	&& Params.VOTE != null && Params.CANCEL != null && Params.MACHINE_ENTRY != null
	  @ 	&& Params.DEFAULT_HOST_BBOARD != null && Params.RESULTS != null && Params.LOG != null
	  @ 	&& vm.votesForCandidates != null && requests != null
	  @ 	&& vm.bb_encryptor != null && vm.signer != null && vm.entryLog != null
	  @ 	&& bb.verifier != null && bb.entryLog != null
	  @ 	&& correctResult != vm.votesForCandidates
	  @ 	&& correctResult != choices0 && correctResult != choices1
	  @ 	&& vm.votesForCandidates != choices0 && vm.votesForCandidates != choices1
	  @ 	&& actions != choices0 && actions != choices1 && actions != correctResult
	  @ 	&& actions != vm.votesForCandidates && audit_choices != choices0
	  @ 	&& audit_choices != choices1 && audit_choices != correctResult
	  @ 	&& audit_choices != vm.votesForCandidates
	  @ 	&& choices0.length == numberOfVoters && choices0.length == choices1.length
	  @ 	&& actions.length == N && audit_choices.length == N && requests.length == N
	  @ 	&& vm.votesForCandidates.length == vm.numberOfCandidates
	  @ 	&& vm.votesForCandidates.length == correctResult.length
	  @ 	&& (\forall int j; 0 <= j && j < vm.numberOfCandidates;
	  @ 		vm.votesForCandidates[j] == 0)
	  @ 	&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 		0 <= choices0[j] && choices0[j] < correctResult.length)
	  @ 	&& (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 		0 <= choices1[j] && choices1[j] < correctResult.length)
	  @ 	&& (\forall int j; 0 <= j && j < correctResult.length;
	  @ 		correctResult[j] ==
	  @ 			(\num_of int k; 0 <= k && k < numberOfVoters; choices0[k] == j))
	  @ 	&& (\forall int j; 0 <= j && j < correctResult.length;
	  @ 		correctResult[j] ==
	  @ 			(\num_of int k; 0 <= k && k < numberOfVoters; choices1[k] == j));
	  @ diverges true;
	  @ assignable Environment.inputCounter, Environment.result, vm.lastBallot,
	  @ 		vm.voteCounter, vm.votesForCandidates[*], flag;
	  @ ensures flag;
	  @ signals (Throwable e) true;
	  @*/
	private static /*@ helper @*/ void innerMain(VotingMachine vm, BulletinBoard bb,
	                                             int numberOfVoters, boolean secret, int[] choices0,
	                                             int[] choices1, final int N, final int[] actions,
	                                             final int[] audit_choices, /*@ nullable @*/ byte[][] requests)
	                throws InvalidVote, NetworkError, InvalidCancelation {
		int voterNr = 0;
		/*@ loop_invariant 0 <= i && i <= N
		  @ 		&& 0 <= voterNr && voterNr <= i && voterNr <= numberOfVoters
		  @ 		&& correctResult != null && vm != null && vm.votesForCandidates != null
		  @ 		&& vm.bb_encryptor != null && vm.signer != null && vm.entryLog != null
		  @ 		&& vm.numberOfCandidates == vm.votesForCandidates.length
		  @ 		&& correctResult.length == vm.votesForCandidates.length
		  @ 		&& (\forall int j; 0 <= j && j < vm.numberOfCandidates;
		  @ 			vm.votesForCandidates[j] ==
		  @ 				(\num_of int k; 0 <= k && k < voterNr;
		  @ 					j == (secret ? choices0[k] : choices1[k])))
		  @ 		&& (\forall int j; 0 <= j && j < numberOfVoters;
		  @ 			0 <= choices0[j] && choices0[j] < correctResult.length)
		  @ 		&& (\forall int j; 0 <= j && j < numberOfVoters;
		  @ 			0 <= choices1[j] && choices1[j] < correctResult.length);
		  @ assignable Environment.inputCounter, Environment.result, vm.lastBallot,
		  @ 		vm.voteCounter, vm.votesForCandidates[*];
		  @ decreases N - i;
		  @*/
		for( int i=0; i<N; ++i ) {
			switch( actions[i] ) {

			case 0: // next voter votes
				if (voterNr<numberOfVoters) {
					/**
					 * JOANA edit: 
					 * A statement like
					 * int choice = secret ? choices0[voterNr] : choices1[voterNr]
					 * is highly problematic from JOANA's perspective: JOANA does not reason
					 * about values and array bounds, so it assumes that both the accesses
					 * to choices0[voterNr] and choices1[voterNr] may fail and lead to a crash
					 * of the whole program (which influences the result because it may or may not
					 * be updated depending on the secret).
					 * In consequence, JOANA cannot exclude that the secret
					 * decides about whether the program crashes or not because it does not know that
					 * e.g. it cannot be the case that voterNr is out of bounds for choices0 but in the
					 * bounds of choices1.
					 * The rewrited version should be conservative (under the assumption that the arrays
					 * have the same lengths). For JOANA it's also fine because the secret only decides
					 * about the actual choice but not about whether the program crashes (at the point at
					 * which the choice is made, the program cannot have crashed).
					 */
					int choice0 = choices0[voterNr];
					int choice1 = choices1[voterNr];
					int choice = secret ? choice0 : choice1;
					vm.collectBallot(choice);
					++voterNr;
				}
				break;

			case 1: // make the voting machine publish the current (encrypted) log
				vm.publishLog();
				break;

			case 2: // audit (this step altogether should not change the result)
				int audit_choice = audit_choices[i];

				/*@ public behaviour
				  @ requires vm != null && vm.votesForCandidates != null
				  @ 	&& vm.bb_encryptor != null && vm.signer != null && vm.entryLog != null
				  @ 	&& audit_choice != null
				  @ 	&& correctResult.length == vm.votesForCandidates.length;
				  @ diverges true;
				  @ assignable Environment.inputCounter, Environment.result, vm.lastBallot,
				  @ 		vm.voteCounter, vm.votesForCandidates[*];
				  @ ensures vm.lastBallot == null && vm.votesForCandidates != null
				  @ 	&& correctResult.length == vm.votesForCandidates.length
				  @ 	&& vm.numberOfCandidates == vm.votesForCandidates.length
				  @ 	&& vm.votesForCandidates.length == \old(vm.votesForCandidates.length)
				  @ 	&& (\forall int j; 0 <= j && j < vm.numberOfCandidates;
				  @ 		vm.votesForCandidates[j] == \old(vm.votesForCandidates[j]));
				  @ signals (InvalidVote e) true;
				  @ signals (ArrayIndexOutOfBoundsException e) true;
				  @ signals (Error e) true;
				  @ signals (NetworkError e) true;
				  @ signals (InvalidCancelation e) true;
				  @ signals (NullPointerException e) true;
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