This package contains source files and additional verification
files for formal verification of an electronic voting system. 


The code
========

The verified Java code of the case study is the folder 'src'.

Note that this code uses ideal functionalities for the u
cryptographic operations and models the interactions of the
untrusted environment (adversary) with the system component, as
described in the section "Privacy Game" of the paper. This code
is, therefore, not meant to be executed (running it does not give
any reasonable results, because many aspects of a run depend on
an untrusted and unpredictable environment which is not
programmed to behave in any reasonable way).


Static IFC check
================

For your convenience, we provide an ant script to perform the
static non-interference verification of the example code, carried
out by Joana.

Requirements:
  * Ant >= 1.9.3
  * Java 1.6+

Make sure that 'java', 'javac' and 'ant' can be executed from
your shell. To invoke the static analysis, just run 'ant' or 'ant
ifc'. This will build the example code and the analysis code and
run the analysis on the example. Additionally, a PDG is produced
for further inspection. If you change the source code and run
'ant' again, the code will be re-compiled and the re-compiled
code will by analyzed.


KeY proofs
==========

Loading the proofs works best with the latest release 2.4.0 of
KeY, that can be downloaded from

  http://key-project.org/download/index.html 

Other versions are not tested. Running KeY requires Java 1.6 or
later.

The folder "proof" contains all proof scripts for the case study.
Each .proof file corresponds to one method in the Java source
that has been verified against a JML specification.  To replay
and investigate the proofs, start KeY and open a .proof file.
This will immediately trigger a proof replay, which may take some
seconds.  After that, you may inspect all proof steps (i.e., rule
applications).

To just check the proof scripts being valid, you may also use KeY
in command line mode (provided that you have a non-JAR version of
KeY).  Type "key --auto-loadonly xx.proof" on the command line.

Comprehensive statistics are provided in the file
proof/statistics.csv, that can be loaded as a CSV table with "|"
as delimiters (but not commas).

To repeat the proofs on your own, load the file project.key in
KeY with GUI.  You are prompted for a verification target (i.e.,
Java method).  All proofs can be found without user interaction;
you may just press the auto mode button (green "play" button).
Note that JML specifications are written in the original Java
sources.


Additional side effect analysis
===============================

As mentioned in Sect. IV-F the paper, we have used results that
calling the logging component only has benign side effects. The
results provided by the PDG computed by Joana are listed in
folder "sideeffects". For each caller context (i.e., calling
method), an upper bound of affected heap locations is listed.
These locations do not appear syntactically in the specification
of the respective methods. Therefore, it can be assumed without
loss of generality that these side effects were not present at
all.

