package de.uni.trier.infsec.eVotingMachine.core;
import de.uni.trier.infsec.utils.MessageTools;


public class EntryQueue {

    /*@ spec_public @*/ static class Node
    {
        public byte[] entry;
        public /*@ nullable @*/ Node next;

        public Node(byte[] entry)
        {
            this.entry = entry;
            this.next=null;
        }
    }

    private /*@ spec_public nullable @*/ Node head, last = null;

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

    /*@ public normal_behaviour
      @ requires (\forall Node n; n.entry != null);
      @ diverges true;
      @ ensures (\forall Node n; n.entry != null);
      @*/
    public /*@ pure helper @*/ byte[] getEntries()
    {
        if(head==null)
            return new byte[]{};
        byte[] entries=head.entry;
        /*@ loop_invariant head != null && entries != null
          @ 			&& (n != null ==> !\fresh(n))
          @ 			&& (\forall Node n; n.entry != null);
          @ assignable entries;
          @*/
        for(Node n=head.next; n!=null; n=n.next)
            entries=MessageTools.concatenate(entries, n.entry);
        return entries;
    }
}