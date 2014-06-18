package de.uni.trier.infsec.eVotingMachine.core;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.functionalities.pkienc.RegisterEnc;
import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkienc.Decryptor;
import de.uni.trier.infsec.functionalities.pkisig.RegisterSig;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.functionalities.pkisig.Verifier;

public final class Setup 
{
	private static VotingMachine VM;

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
		VM = new VotingMachine(numberOfCandidates, audit_encryptor, vm_signer);
		

		// CHOICE VECTORS OF CHOICES AND THE CORRECT RESULT  

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


		for( int i=0; i<numberOfVoters; ++i ) {
			int choice = secret ? choices0[i] : choices1[i];
			VM.collectBallot(choice);
		}
		
		// make the voting machine publish the result:
		VM.publishResult();
		
	}
}