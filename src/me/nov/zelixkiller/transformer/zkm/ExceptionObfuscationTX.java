package me.nov.zelixkiller.transformer.zkm;

import java.util.ArrayList;
import java.util.logging.Level;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import me.nov.zelixkiller.JarArchive;
import me.nov.zelixkiller.ZelixKiller;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.utils.ClassUtils;

public class ExceptionObfuscationTX extends Transformer {

	private int removed;

	@Override
	public boolean isAffected(ClassNode cn) {
		return cn.methods.stream().anyMatch(mn -> !mn.tryCatchBlocks.isEmpty());
	}

	@Override
	public void transform(JarArchive ja, ClassNode cn) {
		cn.methods.forEach(mn -> new ArrayList<>(mn.tryCatchBlocks).forEach(tcb -> check(cn, mn, tcb, tcb.handler)));
	}

	private void check(ClassNode cn, MethodNode mn, TryCatchBlockNode tcb, LabelNode handler) {
		AbstractInsnNode ain = handler;
		while (ain.getOpcode() == -1) { //skip labels and frames
			ain = ain.getNext();
		}
		if(ain.getOpcode() == ATHROW) {
			removeTCB(mn, tcb);
		} else if(ain instanceof MethodInsnNode && ain.getNext().getOpcode() == ATHROW) {
			MethodInsnNode min = (MethodInsnNode) ain;
			if(min.owner.equals(cn.name)) {
				MethodNode getter = ClassUtils.getMethod(cn, min.name, min.desc);
				AbstractInsnNode getterFirst = getter.instructions.getFirst();
				while (getterFirst.getOpcode() == -1) {
					getterFirst = ain.getNext();
				}
				if(getterFirst instanceof VarInsnNode && getterFirst.getNext().getOpcode() == ARETURN) {
					if(((VarInsnNode)getterFirst).var == 0) {
						removeTCB(mn, tcb);
					}
				}
			}
		}
	}

	private void removeTCB(MethodNode mn, TryCatchBlockNode tcb) {
		removed++;
		mn.tryCatchBlocks.remove(tcb);
	}

	@Override
	public void postTransform() {
		ZelixKiller.logger.log(Level.INFO, "Removed " + removed + " TryCatchBlocks successfully");
	}
}
