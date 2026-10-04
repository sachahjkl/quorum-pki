-------------------------- MODULE DistributedPKI --------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC
CONSTANTS Validators, Byzantine, ApprovalQuorum, FinalityQuorum
Proposals == {"issueA", "issueB", "forged", "rotate", "revoke"}
Valid == Proposals \ {"forged"}
Gen(x) == IF x \in {"issueA","issueB","forged"} THEN 1
          ELSE IF x = "rotate" THEN 2 ELSE 3
VARIABLES pending, approvals, votes, finalized, log, previousLog,
          clientSeen, rollbackAttempts, partition, clock, keys
vars == <<pending,approvals,votes,finalized,log,previousLog,
          clientSeen,rollbackAttempts,partition,clock,keys>>
Init == /\ pending = {}
        /\ approvals = [x \in Proposals |-> {}]
        /\ votes = [v \in Validators |-> {}]
        /\ finalized = {}
        /\ log = <<>> /\ previousLog = <<>>
        /\ clientSeen = 0 /\ rollbackAttempts = 0
        /\ partition = {} /\ clock = 0 /\ keys = {}
Ready(x) == IF Gen(x)=1 THEN TRUE
            ELSE IF x="rotate" THEN "issueA" \in finalized
            ELSE "rotate" \in finalized
Propose(x) == /\ x \notin pending /\ Ready(x)
              /\ pending' = pending \cup {x}
              /\ UNCHANGED <<approvals,votes,finalized,log,previousLog,
                             clientSeen,rollbackAttempts,partition,clock,keys>>
Approve(v,x) == /\ x \in pending /\ v \notin partition
                /\ v \notin approvals[x]
                /\ (v \in Byzantine \/ x \in Valid)
                /\ approvals' = [approvals EXCEPT ![x] = @ \cup {v}]
                /\ UNCHANGED <<pending,votes,finalized,log,previousLog,
                               clientSeen,rollbackAttempts,partition,clock,keys>>
Vote(v,x) == /\ x \in pending /\ v \notin partition /\ Ready(x)
             /\ Cardinality(approvals[x]) >= ApprovalQuorum
             /\ x \notin votes[v]
             /\ (v \in Byzantine \/
                  ~\E y \in votes[v] : Gen(y)=Gen(x))
             /\ votes' = [votes EXCEPT ![v] = @ \cup {x}]
             /\ UNCHANGED <<pending,approvals,finalized,log,previousLog,
                            clientSeen,rollbackAttempts,partition,clock,keys>>
Voters(x) == {v \in Validators : x \in votes[v]}
Commit(x) == /\ x \in pending /\ x \notin finalized /\ Ready(x)
             /\ Cardinality(Voters(x)) >= FinalityQuorum
             /\ finalized' = finalized \cup {x}
             /\ previousLog' = log /\ log' = Append(log,x)
             /\ keys' = IF x="rotate" THEN {"A","NEXT"}
                         ELSE IF x="revoke" THEN {}
                         ELSE {x}
             /\ UNCHANGED <<pending,approvals,votes,clientSeen,
                            rollbackAttempts,partition,clock>>
Observe(x) == /\ x \in finalized /\ Gen(x)>clientSeen
              /\ clientSeen' = Gen(x)
              /\ UNCHANGED <<pending,approvals,votes,finalized,log,previousLog,
                             rollbackAttempts,partition,clock,keys>>
Rollback == /\ clientSeen>1 /\ rollbackAttempts=0
            /\ rollbackAttempts'=1
            /\ UNCHANGED <<pending,approvals,votes,finalized,log,previousLog,
                           clientSeen,partition,clock,keys>>
Partition(s) == /\ s \subseteq Validators /\ s # partition
                /\ partition'=s
                /\ UNCHANGED <<pending,approvals,votes,finalized,log,previousLog,
                               clientSeen,rollbackAttempts,clock,keys>>
Tick == /\ "rotate" \in finalized /\ clock<2
        /\ clock'=clock+1
        /\ keys'=IF "revoke" \in finalized THEN {} ELSE
                  IF clock'=2 THEN {"NEXT"} ELSE keys
        /\ UNCHANGED <<pending,approvals,votes,finalized,log,previousLog,
                       clientSeen,rollbackAttempts,partition>>
Next == (\E x \in Proposals: Propose(x) \/ Commit(x) \/ Observe(x))
        \/ (\E v \in Validators,x \in Proposals: Approve(v,x) \/ Vote(v,x))
        \/ (\E s \in { {}, {CHOOSE v \in Validators: TRUE} }: Partition(s))
        \/ Rollback \/ Tick
Spec == Init /\ [][Next]_vars
TypeOK == /\ pending \subseteq Proposals /\ finalized \subseteq Proposals
          /\ log \in Seq(Proposals) /\ clientSeen \in 0..3
          /\ partition \subseteq Validators /\ clock \in 0..2
CommittedHasQuorum == \A x \in finalized:
 Cardinality(approvals[x])>=ApprovalQuorum /\ Cardinality(Voters(x))>=FinalityQuorum
MinorityCannotForge == "forged" \notin finalized
UniqueFinality == \A x,y \in finalized: Gen(x)=Gen(y) => x=y
AppendOnly == SubSeq(log,1,Len(previousLog))=previousLog
NoRollback == rollbackAttempts=1 => clientSeen>=2
RotationContinuity == ("rotate" \in finalized /\ "revoke" \notin finalized /\ clock<2)
                       => {"A","NEXT"} \subseteq keys
=============================================================================
