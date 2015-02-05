README on KeY proofs
---------------------

Loading the proofs best works with the latest release 2.4,
that can be downloaded from http://key-project.org/download/index.html
Other versions are not tested.

The folder "proof" contains all proof scripts for the case study.
Each .proof file corresponds to one method in the Java source
that has been verified against a JML specification.
To replay and investigate the proofs, start KeY and open a .proof file.
This will immediately trigger a proof replay, which may take some seconds.
After that, you may inspect all proof steps (i.e., rule applications).

To just check the proof scripts being valid, you may also use KeY in command
line mode (provided that you have a non-JAR version of KeY). 
Type "key --auto-loadonly xx.proof" on the command line.

Comprehensive statistics are provided in the file proof/statistics.csv,
that can be loaded as a CSV table with "|" as delimiters (but not commas).

To repeat the proofs on your own, load the file project.key in KeY with GUI.
You are prompted for a verification target (i.e., Java method).
All proofs can be found without user interaction; you may just press the
auto mode button (green "play" button).
Note that JML specifications are written in the original Java sources.
