package me.nov.zelixkiller.transformer.zkm11;

import java.util.logging.Level;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;

import me.nov.zelixkiller.JarArchive;
import me.nov.zelixkiller.ZelixKiller;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.utils.analysis.ConstantTracker;
import me.nov.zelixkiller.utils.analysis.ConstantTracker.ConstantValue;

public class ControlFlowT11 extends Transformer {

	public int success = 0;
	public int failures = 0;
	private int jumps = 0;

	@Override
	public boolean isAffected(ClassNode cn) {
		return !cn.methods.isEmpty();
	}

	@Override
	public void transform(JarArchive ja, ClassNode cn) {
		cn.methods.forEach(mn -> {
			if (mn.instructions.size() > 3) {
				AbstractInsnNode first = mn.instructions.getFirst();
				if (first.getOpcode() == INVOKESTATIC && first.getNext().getOpcode() == ISTORE) {
					MethodInsnNode min = (MethodInsnNode) first;
					if (min.desc.equals("()I")) {
						AbstractInsnNode ain = getNumberPush(min, ((VarInsnNode) first.getNext()).var);
						if (ain != null) {
							mn.instructions.set(first, ain);
						}
					}
				}
			}
		});
		cn.methods.forEach(mn -> {
			Analyzer<ConstantValue> a = new Analyzer<>(new ConstantTracker());
			try {
				a.analyze(cn.name, mn);
			} catch (Exception e) {
				failures++;
				return;
			}
			Frame<ConstantValue>[] frames = a.getFrames();
			int i = 0;
			for (AbstractInsnNode ain : mn.instructions.toArray()) {
				Frame<ConstantValue> frame = frames[i++];
				int op = ain.getOpcode();
				if (op == IFEQ || op == IFNE) {
					ConstantValue v = frame.getStack(frame.getStackSize() - 1);
					if (v.getValue() != null) {
						boolean zero = (int)v.getValue() == 0;
						if (op == IFEQ) {
							if(!zero) {
								mn.instructions.set(ain, new InsnNode(POP));
							} else {
								mn.instructions.insertBefore(ain, new InsnNode(POP));
								mn.instructions.set(ain, new JumpInsnNode(GOTO, ((JumpInsnNode)ain).label));
							}
						} else {
							if(zero) {
								mn.instructions.set(ain, new InsnNode(POP));
							} else {
								mn.instructions.insertBefore(ain, new InsnNode(POP));
								mn.instructions.set(ain, new JumpInsnNode(GOTO, ((JumpInsnNode)ain).label));
							}
						}
						jumps++;
					}
				}
			}
			success++;
		});
	}

	private AbstractInsnNode getNumberPush(MethodInsnNode min, int var) {
		// TODO find out by invoking if it can't be identified by patterns in future versions
		AbstractInsnNode ain = min;
		while (ain != null) {
			if (ain instanceof VarInsnNode) {
				if (((VarInsnNode) ain).var == var) {
					int nextOp = ain.getNext().getOpcode();
					// jump should never happen
					if (nextOp == IFEQ) {
						return new InsnNode(ICONST_1);
					} else if (nextOp == IFNE) {
						return new InsnNode(ICONST_0);
					}
				}
			}
			ain = ain.getNext();
		}
		return null;
	}

	@Override
	public void postTransform() {
		ZelixKiller.logger.log(Level.INFO, "Succeeded in " + success + " classes, failed in " + failures);
		ZelixKiller.logger.log(Level.INFO, "Removed " + jumps + " redundant jumps, please clean code afterwards");
	}

}
