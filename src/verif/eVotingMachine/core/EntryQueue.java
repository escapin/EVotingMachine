package verif.eVotingMachine.core;
import verif.utils.MessageTools;


public class EntryQueue {

    /*@ spec_public @*/ static class Node
    {
        public /*@ nullable @*/ byte[] entry;
        public /*@ nullable @*/ Node next;

        /*@ public normal_behaviour
          @ requires true;
          @ assignable this.entry, this.next;
          @ ensures this.entry == entry && this.next == null;
          @*/
        public Node(/*@ nullable @*/ byte[] entry)
        {
            this.entry = entry;
            this.next=null;
        }
    }

    private /*@ spec_public nullable @*/ Node head, last = null;

    /*@ public normal_behaviour
      @ requires head == null;
      @ assignable head, last;
      @ ensures head != null && last != null
      @ 	&& head.entry == entry && last.entry == entry
      @ 	&& \fresh(head) && \fresh(last);
      @ also
      @ public normal_behaviour
      @ requires head != null && last != null;
      @ assignable last, last.next;
      @ ensures last != null && last.entry == entry && \fresh(last);
      @ also
      @ public exceptional_behaviour
      @ requires head != null && last == null;
      @ diverges true;
      @ signals_only NullPointerException;
      @ assignable \nothing;
      @ signals (NullPointerException e) true;
      @*/
    public /*@ helper @*/ void add(/*@ nullable @*/ byte[] entry)
    {
        Node newEntry=new Node(entry);
        if(head==null)
            head=last=newEntry;
        else {
            last.next=newEntry;
            last=newEntry;
        }
    }

    /*@ public behaviour
      @ requires true;
      @ diverges true;
      @ signals_only NullPointerException;
      @ ensures true;
      @ signals (NullPointerException e) true;
      @*/
    public /*@ pure helper nullable @*/ byte[] getEntries()
    {
        if(head==null)
            return new byte[]{};
        byte[] entries=head.entry;
        /*@ loop_invariant head != null;
          @ assignable entries;
          @*/
        for(Node n=head.next; n!=null; n=n.next)
            entries=MessageTools.concatenate(entries, n.entry);
        return entries;
    }
}