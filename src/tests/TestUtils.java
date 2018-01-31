package tests;

import junit.framework.TestCase;
import utils.MessageTools;
import utils.Utilities;

import org.junit.Test;


public class TestUtils extends TestCase {

	@Test
	public void testLongByteConversion()
	{
		
//		for(int i=0; i<8; i++)
//			System.out.println((long) 1 << (i*8));
		long valueLong=-7;
		byte[] byteLong=MessageTools.longToByteArray(valueLong);
		System.out.println();
		long valueBack = MessageTools.byteArrayToLong(byteLong);
		System.out.println();
		System.out.println(new String(byteLong.toString()));
		System.out.println(valueBack);
		assertTrue(valueLong==valueBack);
		
//		int valueInt=1000000;
//		byte[] byteInt=MessageTools.intToByteArray(valueInt);
//		System.out.println(byteInt);
//		System.out.println(MessageTools.byteArrayToInt(byteInt));
	}
}
