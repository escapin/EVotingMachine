package verif.eVotingMachine.core;

public class Params {
	
	public static final int AUDITORS_ID = 1;
	public static final int VOTING_MACHINE_ID = 2;
	public static final int BULLETIN_BOARD_ID = 3;
	
	public static final byte[] ENC_DOMAIN = {0x00};
	public static final byte[] SIG_DOMAIN = {0x01};
	
	public static byte[] VOTE = {0x02};
	public static byte[] CANCEL = {0x03};
	public static byte[] LOG = {0x04};
	public static byte[] RESULTS = {0x05};
	public static byte[] MACHINE_ENTRY = {0x06};
	
	
	
	public static final int LISTEN_PORT_BBOARD = 4092;	// Listen port for result requests
	public static final String DEFAULT_HOST_BBOARD = "localhost";
}
