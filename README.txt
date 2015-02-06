This package contains source files and additional verification
files for formal verification of an electronic voting system. 

The sources are in the folder src.

static IFC check
================

For your convenience, we provide an ant script to perform the static non-interference verification of the example code.

Requirements:
  * Ant >= 1.9.3
  * Java 1.6+

Make sure that 'java', 'javac' and 'ant' can be executed from your shell. To invoke the static analysis, just run 'ant' or 'ant ifc'. This will build the example code and the analysis code and run the analysis on the example. Additionally, a PDG is produced for further inspection. If you change the source code and run 'ant' again, the code will be re-compiled and the re-compiled code will by analyzed.


[PLEASE COMPLETE]

