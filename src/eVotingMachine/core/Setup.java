package eVotingMachine.core;

import environment.Environment;
import funct.pkienc.Decryptor;
import funct.pkienc.Encryptor;
import funct.pkienc.RegisterEnc;
import funct.pkisig.RegisterSig;
import funct.pkisig.Signer;
import funct.pkisig.Verifier;

public class Setup {
	private static VotingMachine VM;
	private static BulletinBoard BB;

	// one secret bit
	private static boolean secret;

	// the correct result
	static int[] correctResult; // CONSERVATIVE EXTENSION

	private static int[] createChoices(int numberOfVoters, int numberOfCandidates) {
		final int[] choices = new int[numberOfVoters];
		for (int i=0; i<numberOfVoters; ++i) {
			choices[i] = Environment.untrustedInput();
		}
		return choices;
	}

	private static int[] computeResult (int[] choices, int numberOfCandidates) {
		int[] res = new int[numberOfCandidates];
		for (int i=0; i<choices.length; i++) 
			++res[choices[i]];
		return res;
	}

	private static boolean equalResult(int[] r1, int[] r2) {
		for (int j= 0; j<r1.length; j++)
			if (r1[j]!=r2[j]) return false;
		return true;
	}

	public static void main (String[] a) throws Throwable {

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
		VM = new VotingMachine(numberOfCandidates, audit_encryptor, vm_signer);
		BB = new BulletinBoard(vm_verifier);
  

		// let the environment determine two vectors of choices
		int[] choices0 = createChoices(numberOfVoters, numberOfCandidates);
		int[] choices1 = createChoices(numberOfVoters, numberOfCandidates);

		// check that those vectors give the same result
		int[] r0 = computeResult(choices0, numberOfCandidates);
		int[] r1 = computeResult(choices1, numberOfCandidates);
		if (!equalResult(r0,r1))
			throw new Throwable();	// abort if the vectors do not yield the same result

		// store correct result
		correctResult = r1; // CONSERVATIVE EXTENSTION


		// the main loop
		
		final int N = Environment.untrustedInput(); // the environment decides for how long the system runs
		int voterNr = 0;
		for( int i=0; i<N; ++i ) {
			int action = Environment.untrustedInput();
			switch( action ) {

			// This is the essential step.
			// Importantly, the vote collection is done directly in the method collectBallot (without
			// first sending the choice to any server).
			case 0: // the next voter votes
				if (voterNr<numberOfVoters) {
					int choice = secret ? choices0[voterNr] : choices1[voterNr];
					VM.collectBallot(choice);
					++voterNr;
				}
				break;

			case 1: // make the voting machine publish the current (encrypted) log
				VM.publishLog();
				break;

		    // It would be good to keep this step
			case 2: // audit (this step altogether should not change the result)
				int audit_choice = Environment.untrustedInput();
				int sqnumber = VM.collectBallot(audit_choice);
				Environment.untrustedOutput(sqnumber);
				VM.publishLog();
				VM.cancelLastBallot();
				break;

			// The following steps are not so essential. If problematic, we can remove (move them after the loop) them.

			case 3: // deliver a message to the bulletin board
				byte[] request = Environment.untrustedInputMessage();
				BB.onPost(request);
				break;

			case 4: // make the bulleting board send its content over the network
				BB.onRequestContent();
				break;
			}
		}

		// make the voting machine publish the result (only if all the voters have voted):
		if (voterNr == numberOfVoters)
			VM.publishResult();

	}
}