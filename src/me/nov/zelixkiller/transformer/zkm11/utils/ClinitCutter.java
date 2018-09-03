package me.nov.zelixkiller.transformer.zkm11.utils;

import java.util.ArrayList;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;

import me.nov.zelixkiller.utils.MethodUtils;

public class ClinitCutter implements Opcodes {
	public static InsnList cutClinit(MethodNode mn) {
		InsnList insns = MethodUtils.copy(mn.instructions, null, null);
		ArrayList<LabelNode> handlers = new ArrayList<>();
		for (TryCatchBlockNode tcbn : mn.tryCatchBlocks) {
			handlers.add((LabelNode) insns.get(mn.instructions.indexOf(tcbn.handler)));
		}
		for(LabelNode ln : handlers) {
			findSubroutinesAndDelete(insns, ln);
		}
		AbstractInsnNode endLabel = findEndLabel(insns);
		while (endLabel.getOpcode() == -1) {
			endLabel = endLabel.getNext();
		}
		AbstractInsnNode end = endLabel.getPrevious();
		if (endLabel.getOpcode() != RETURN) {
			findSubroutinesAndDelete(insns, endLabel);
			insns.insert(end, new InsnNode(RETURN));
		}
		return insns;
	}

	private static void findSubroutinesAndDelete(InsnList insns, AbstractInsnNode ain) {
		if (!insns.contains(ain)) {
			return;
		}
		while (ain != null && !(ain instanceof JumpInsnNode) && !(ain instanceof TableSwitchInsnNode)
				&& !(ain instanceof LookupSwitchInsnNode)) {
			AbstractInsnNode next = ain.getNext();
			insns.remove(ain);
			ain = next;
		}
		if (ain == null) {
			return;
		}
		if (ain instanceof JumpInsnNode) {
			AbstractInsnNode jumpTo = ((JumpInsnNode) ain).label;
			if (ain.getOpcode() != GOTO) {
				// ifs can also be false
				findSubroutinesAndDelete(insns, ain.getNext());
			}
			insns.remove(ain);
			findSubroutinesAndDelete(insns, jumpTo);
		} else if (ain instanceof TableSwitchInsnNode) {
			// untested!
			TableSwitchInsnNode tsin = (TableSwitchInsnNode) ain;
			insns.remove(ain);
			for (LabelNode ln : tsin.labels) {
				findSubroutinesAndDelete(insns, ln);
			}
			findSubroutinesAndDelete(insns, tsin.dflt);
		} else if (ain instanceof LookupSwitchInsnNode) {
			// untested!
			LookupSwitchInsnNode lsin = (LookupSwitchInsnNode) ain;
			insns.remove(ain);
			for (LabelNode ln : lsin.labels) {
				findSubroutinesAndDelete(insns, ln);
			}
			findSubroutinesAndDelete(insns, lsin.dflt);
		}
	}

	public static AbstractInsnNode findEndLabel(InsnList insns) {
		AbstractInsnNode ain = insns.getFirst();
		while (ain != null) {
			if (ain.getOpcode() == GOTO && ain.getPrevious() != null
					&& (blockContainsSetter(ain.getPrevious()) || ain.getPrevious().getOpcode() == ASTORE)) {
				return ((JumpInsnNode) ain).label;
			}
			ain = ain.getNext();
		}
		ain = insns.getLast();
		while (ain != null) {
			if (ain.getOpcode() == IF_ICMPGE && ain.getPrevious() != null && (ain.getPrevious().getOpcode() == ILOAD)) {
				return ((JumpInsnNode) ain).label;
			}
			ain = ain.getPrevious();
		}
		throw new RuntimeException();
	}

	private static boolean blockContainsSetter(AbstractInsnNode ain) {
		if (ain.getOpcode() == PUTSTATIC && ((FieldInsnNode) ain).desc.endsWith("Ljava/lang/String;")) {
			return true;
		}
		AbstractInsnNode ain2 = ain;
		while (ain2 != null && !(ain2 instanceof LabelNode)) {
			if (ain2.getOpcode() == PUTSTATIC && ain2.getPrevious().getOpcode() == ANEWARRAY) {
				FieldInsnNode fin = (FieldInsnNode) ain2;
				if (fin.desc.endsWith("[Ljava/lang/String;"))
					return true;
			}
			ain2 = ain2.getPrevious();
		}
		return false;
	}
}
