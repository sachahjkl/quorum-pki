------------------------ MODULE QuorumIntersection ------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Validators, Byzantine, Quorum
Quorums == {q \in SUBSET Validators : Cardinality(q)>=Quorum}
ASSUME Byzantine \subseteq Validators
VARIABLE pair
Init == pair \in Quorums \X Quorums
Next == UNCHANGED pair
Spec == Init /\ [][Next]_pair
HonestIntersection == (pair[1] \cap pair[2]) \ Byzantine # {}
=============================================================================
