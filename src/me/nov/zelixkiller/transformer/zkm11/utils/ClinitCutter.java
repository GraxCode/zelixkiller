package me.nov.zelixkiller.transformer.zkm11.utils;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;

import me.nov.zelixkiller.utils.MethodUtils;

public class ClinitCutter implements Opcodes {
	public static InsnList cutClinit(InsnList instructions) {
		InsnList insns = MethodUtils.copy(instructions, null, null);
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
		while (ain != null && !(ain instanceof JumpInsnNode)) {
			AbstractInsnNode next = ain.getNext();
			insns.remove(ain);
			ain = next;
		}
		if (ain == null) {
			return;
		}
		AbstractInsnNode jumpTo = ((JumpInsnNode) ain).label;
		if (ain.getOpcode() != GOTO) {
			// ifs can also be false
			findSubroutinesAndDelete(insns, ain.getNext());
		}
		insns.remove(ain);
		findSubroutinesAndDelete(insns, jumpTo);
	}

	public static AbstractInsnNode findEndLabel(InsnList insns) {
		AbstractInsnNode ain = insns.getLast();
		while (ain != null) {
			if (ain.getOpcode() == GOTO && ain.getPrevious() != null
					&& (ain.getPrevious().getOpcode() == PUTSTATIC || ain.getPrevious().getOpcode() == ASTORE || ain.getPrevious().getOpcode() == ISTORE)) {
				return ((JumpInsnNode) ain).label;
			}
			ain = ain.getPrevious();
		}
		throw new RuntimeException();
	}
}
