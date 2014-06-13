package de.uni.trier.infsec.tests;



import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import junit.framework.TestCase;
import org.junit.Test;
import org.junit.After;

import de.uni.trier.infsec.eVotingMachine.core.BulletinBoard;
import de.uni.trier.infsec.eVotingMachine.core.Params;
import de.uni.trier.infsec.eVotingMachine.core.VotingMachine;
import de.uni.trier.infsec.eVotingMachine.core.VotingMachine.InvalidVote;
import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pki.PKIServerCore;
import de.uni.trier.infsec.functionalities.pkienc.Decryptor;
import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkienc.RegisterEnc;
import de.uni.trier.infsec.functionalities.pkienc.RegisterEnc.PKIError;
import de.uni.trier.infsec.functionalities.pkisig.RegisterSig;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.functionalities.pkisig.Verifier;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.network.NetworkServer;
import de.uni.trier.infsec.utils.Utilities;





public class TestVotingMachine extends TestCase  
{
	
	private VotingMachine vm;
	private BulletinBoard bb;
	private static int numberOfCandidate=2;
	
	@Test
	public void testVoting() throws Exception 
	{
		NetworkServer.listenForRequests(Params.LISTEN_PORT_BBOARD);
		
		vm.collectBallot(0);
		byte[] request=null;
		do{
			request=NetworkServer.nextRequest(Params.LISTEN_PORT_BBOARD);
		}
		while(request==null);
		bb.onPost(request);
		
		assertTrue(Utilities.arrayEqual(vm.getLastSentMessage(),bb.getLastReceivedMessage()));
		
		vm.collectBallot(1);
		assertFalse(Utilities.arrayEqual(vm.getLastSentMessage(),bb.getLastReceivedMessage()));
		request=null;
		do{
			request=NetworkServer.nextRequest(Params.LISTEN_PORT_BBOARD);
		}
		while(request==null);
		bb.onPost(request);
		
		assertTrue(Utilities.arrayEqual(vm.getLastSentMessage(),bb.getLastReceivedMessage()));
		
		try{
			vm.collectBallot(2);
			fail("Revoking -- exception expected");
		} catch(InvalidVote e){}
		
		
		vm.collectBallot(1);
		request=null;
		do{
			request=NetworkServer.nextRequest(Params.LISTEN_PORT_BBOARD);
		}
		while(request==null);
		bb.onPost(request);
		assertTrue(Utilities.arrayEqual(vm.getLastSentMessage(),bb.getLastReceivedMessage()));

		vm.cancelLastBallot();
		request=null;
		do{
			request=NetworkServer.nextRequest(Params.LISTEN_PORT_BBOARD);
		}
		while(request==null);
		bb.onPost(request);
		assertTrue(Utilities.arrayEqual(vm.getLastSentMessage(),bb.getLastReceivedMessage()));
		
		vm.publishResult();
		request=null;
		do{
			request=NetworkServer.nextRequest(Params.LISTEN_PORT_BBOARD);
		}
		while(request==null);
		bb.onPost(request);
		assertTrue(Utilities.arrayEqual(vm.getLastSentMessage(),bb.getLastReceivedMessage()));
		
		vm.publishLog();
		request=null;
		do{
			request=NetworkServer.nextRequest(Params.LISTEN_PORT_BBOARD);
		}
		while(request==null);
		bb.onPost(request);
		assertTrue(Utilities.arrayEqual(vm.getLastSentMessage(),bb.getLastReceivedMessage()));
	}
	
	@Override
	protected void setUp() throws Exception 
	{
		super.setUp();
		// if the db already exists, we delete it
		Path dir = FileSystems.getDefault().getPath(PKIServerCore.DEFAULT_DATABASE);
		try{
			Files.delete(dir);
		}catch (NoSuchFileException e){
			//if it doesn't, we don't do anything
		}
		
		PKI.useLocalMode();
		Decryptor bb_decryptor = new Decryptor();
		RegisterEnc.registerEncryptor(bb_decryptor.getEncryptor(), Params.BULLETIN_BOARD_ID, Params.ENC_DOMAIN);
		
		Signer vm_signer = new Signer();
		RegisterSig.registerVerifier(vm_signer.getVerifier(), Params.VOTING_MACHINE_ID, Params.SIG_DOMAIN);
		
		
		vm = createVotingMachine(numberOfCandidate, vm_signer);
		bb = createBulletinBoard(bb_decryptor);
	}
	
	private static VotingMachine createVotingMachine(int numberOfCandidate, Signer signer) throws Exception
	{
		Encryptor bb_encryptor=RegisterEnc.getEncryptor(Params.BULLETIN_BOARD_ID,Params.ENC_DOMAIN);
		VotingMachine voting_machine=new VotingMachine(numberOfCandidate, bb_encryptor, signer);
		
		return voting_machine;
		
	}
	
	private static BulletinBoard createBulletinBoard(Decryptor decryptor) throws Exception
	{
		Verifier vm_verifier=RegisterSig.getVerifier(Params.VOTING_MACHINE_ID, Params.SIG_DOMAIN);
		BulletinBoard bulletin_board=new BulletinBoard(vm_verifier);
		
		return bulletin_board;
	}
}
