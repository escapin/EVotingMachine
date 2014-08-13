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
	  @ ensures (\forall int j; 0 <= j && j < numberOfVoters;
	  @ 			0 <= \result[j] && \result[j] < numberOfCandidates);
	  @ ensures \result.length == numberOfVoters;
	  @ diverges true;
	  @ signals_only Throwable;
	  @*/
	private static int[] createChoices(int numberOfVoters, int numberOfCandidates) {
		final int[] choices = new int[numberOfVoters];
		for (int i=0; i<numberOfVoters; ++i) {
			choices[i] = Environment.untrustedInput(numberOfCandidates);
		}
		return choices;
	}

	private static int[] computeResult (int[] choices, int numberOfCandidates) {
		int[] res = new int[numberOfCandidates];
		for (int i=0; i<choices.length; i++) 
			++res[choices[i]];
		return res;
	}

	/*@ private behaviour
	  @ requires r1.length == r2.length;
	  @ ensures \result == (\forall int i; 0 <= i && i < r1.length; r1[i] == r2[i]);
	  @*/
	private static /*@ strictly_pure */ boolean equalResult(int[] r1, int[] r2) {
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
	  @ signals_only Throwable;
	  @ diverges true;
	  @*/
	private static void main2(VotingMachine vm, BulletinBoard bb, int numberOfCandidates,
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
		mainLoop(vm, bb, numberOfCandidates, numberOfVoters, secret, choices0, choices1);
	}

	/*@ private behaviour
	  @ requires equalResult(computeResult(choices0, numberOfCandidates),
	  @						 computeResult(choices1, numberOfCandidates));
	  @ ensures flag;
	  @*/
	private static void mainLoop (VotingMachine vm, BulletinBoard bb, int numberOfCandidates,
								  int numberOfVoters, boolean secret, int[] choices0, int[] choices1)
			throws Throwable, InvalidVote, NetworkError, InvalidCancelation {
		final int N = Environment.untrustedInput(); // the environment decides how long the system runs
		final int[] actions = Environment.untrustedInputArray(N);
		final int[] audit_choices = Environment.untrustedInputArray(N);
		byte[][] requests = Environment.untrustedInputMessages(N);
		main4(vm, bb, numberOfVoters, secret, choices0, choices1, N, actions,
				audit_choices, requests);
	}

	/*@ private behaviour
	  @ ensures flag;
	  @*/
	private static void main4(VotingMachine vm, BulletinBoard bb,
							  int numberOfVoters, boolean secret, int[] choices0,
							  int[] choices1, final int N, final int[] actions,
							  final int[] audit_choices, byte[][] requests)
			throws InvalidVote, NetworkError, InvalidCancelation {
		int voterNr = 0;
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
				int sqnumber = vm.collectBallot(audit_choice);
				Environment.untrustedOutput(sqnumber);
				vm.publishLog();
				vm.cancelLastBallot();
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