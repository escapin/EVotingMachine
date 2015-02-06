package static_ifc;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collection;

import com.ibm.wala.ipa.callgraph.pruned.DoNotPrune;
import com.ibm.wala.ipa.cha.ClassHierarchyException;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.NullProgressMonitor;
import com.ibm.wala.util.collections.Pair;
import com.ibm.wala.util.graph.GraphIntegrity.UnsoundGraphException;

import edu.kit.joana.api.IFCAnalysis;
import edu.kit.joana.api.lattice.BuiltinLattices;
import edu.kit.joana.api.sdg.SDGCall;
import edu.kit.joana.api.sdg.SDGConfig;
import edu.kit.joana.api.sdg.SDGInstruction;
import edu.kit.joana.api.sdg.SDGProgram;
import edu.kit.joana.ifc.sdg.core.SecurityNode;
import edu.kit.joana.ifc.sdg.core.violations.IViolation;
import edu.kit.joana.ifc.sdg.graph.SDGSerializer;
import edu.kit.joana.ifc.sdg.util.JavaMethodSignature;
import edu.kit.joana.util.Stubs;
import edu.kit.joana.wala.core.SDGBuilder.ExceptionAnalysis;
import edu.kit.joana.wala.core.SDGBuilder.FieldPropagation;
import edu.kit.joana.wala.core.SDGBuilder.PointsToPrecision;

public class VerifyEVotingMachine {

	private static final String MAIN_CLASS = "de.uni.trier.infsec.eVotingMachine.core.Setup";
	private static final String METHOD_WITH_SECRET_ARG = "de.uni.trier.infsec.eVotingMachine.core.Setup.main2(Lde/uni/trier/infsec/eVotingMachine/core/VotingMachine;Lde/uni/trier/infsec/eVotingMachine/core/BulletinBoard;IIZ)V";
	private static final String ENV_CLASS = "Lde/uni/trier/infsec/environment/Environment";

	public static void main(String[] args) throws ClassHierarchyException, IOException, UnsoundGraphException, CancelException {
		if (args.length != 2) {
			throw new RuntimeException("provide classpath and PDG file!");
		}
		String classPath = args[0];
		JavaMethodSignature entryMethod = JavaMethodSignature.mainMethodOfClass(MAIN_CLASS);
		SDGConfig config = new SDGConfig(classPath, entryMethod.toBCString(), Stubs.JRE_14);
		config.setPointsToPrecision(PointsToPrecision.N1_OBJECT_SENSITIVE);
		config.setFieldPropagation(FieldPropagation.OBJ_GRAPH_NO_MERGE_AT_ALL);
		config.setPruningPolicy(new DoNotPrune());
		config.setExceptionAnalysis(ExceptionAnalysis.INTERPROC);
		FindStaticFieldAccesses find = new FindStaticFieldAccesses(FieldReference.findOrCreate(ClassLoaderReference.Application, ENV_CLASS, "result", "Z"));
		config.setCGConsumer(find);
		final SDGProgram program = SDGProgram.createSDGProgram(config, System.out, new NullProgressMonitor());
		SDGSerializer.toPDGFormat(program.getSDG(), new FileOutputStream(args[1]));
		IFCAnalysis ana = new IFCAnalysis(program);
		// secret source: fifth parameter of method METHOD_WITH_SECRET_ARG
		for (SDGCall c : 
			program
				.getCallsToMethod(JavaMethodSignature
						.fromString(METHOD_WITH_SECRET_ARG))) {
			ana.addSourceAnnotation(c.getActualParameter(5), BuiltinLattices.STD_SECLEVEL_HIGH);
		}

		// public sinks: every instruction which writes the static field ENV_CLASS.result 
		for (Pair<String, Integer> acc : find.getResult()) {
			for (SDGInstruction i : program.getInstruction(JavaMethodSignature.fromString(acc.fst), acc.snd)) {
				ana.addSinkAnnotation(i, BuiltinLattices.STD_SECLEVEL_LOW);
			}
		}
		Collection<? extends IViolation<SecurityNode>> result = ana.doIFC();
		System.out.println(String.format("%d violation(s) found.", result.size()));
	}
}
