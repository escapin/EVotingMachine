package static_ifc;
import java.util.ArrayList;

import com.ibm.wala.classLoader.IBytecodeMethod;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.shrikeCT.InvalidClassFileException;
import com.ibm.wala.ssa.IR;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.SSAPutInstruction;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.util.collections.Pair;

import edu.kit.joana.wala.core.CGConsumer;

/**
 * Helper class which finds all places in a given program, where a given static field is written.
 */
public class FindStaticFieldAccesses implements CGConsumer {
	private ArrayList<Pair<String, Integer>> accesses = new ArrayList<Pair<String, Integer>>();

	private final FieldReference field;

	public FindStaticFieldAccesses(FieldReference field) {
		this.field = field;
	}

	@Override
	public void consume(CallGraph cg, PointerAnalysis<? extends InstanceKey> pts) {
		for (CGNode n : cg) {
			if (!(n.getMethod() instanceof IBytecodeMethod) || n.getIR() == null) {
				// skip synthetic methods
				continue;
			} else {
				IR ir = n.getIR();
				IBytecodeMethod bcMethod = (IBytecodeMethod) n.getMethod();
				FindStaticAccessesInMethod visitor = new FindStaticAccessesInMethod(bcMethod);
				ir.visitAllInstructions(visitor);
			}
		}
	}

	public ArrayList<Pair<String, Integer>> getResult() {
		return accesses;
	}

	private class FindStaticAccessesInMethod extends SSAInstruction.Visitor {
		private final IBytecodeMethod bcMethod;

		public FindStaticAccessesInMethod(IBytecodeMethod bcMethod) {
			super();
			this.bcMethod = bcMethod;
		}

		@Override
		public void visitPut(SSAPutInstruction put) {
			if (put.isStatic()) {
				if (put.getDeclaredField().equals(field)) {
					try {
						accesses.add(Pair.make(bcMethod.getSignature(), bcMethod.getBytecodeIndex(put.iindex)));
					} catch (InvalidClassFileException e) {
						e.printStackTrace();
						return;
					}
				}
			}
		}

	}
}
