package eVotingMachine.core;
import static utils.MessageTools.concatenate;


public class EntryQueue {

		static class Node 
		{
			public byte[] entry;
			public Node next;

			public Node(byte[] entry) 
			{
				this.entry = entry;
				this.next=null;
			}
		}

		private Node head, last = null;

		public void add(byte[] entry) 
		{
			Node newEntry=new Node(entry);
			if(head==null)
				head=last=newEntry;
			else {
				last.next=newEntry;
				last=newEntry;
			}
		}
		
		public byte[] getEntries()
		{
			if(head==null) 
				return new byte[]{};
			byte[] entries=head.entry;
			for(Node n=head.next; n!=null; n=n.next)
				entries=concatenate(entries, n.entry);
			return entries;
		}		
	}