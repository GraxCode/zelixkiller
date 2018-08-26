package me.nov.zelixkiller.utils;

import java.util.Arrays;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;

public class InsnUtils implements Opcodes {
	public static boolean matches(InsnList il, int[] pattern) {
		AbstractInsnNode ain = il.getFirst();
		for (int i = 0; i < pattern.length; i++) {
			if (ain == null) {
				return false;
			}
			if (ain.getOpcode() != pattern[i]) {
				return false;
			}
			ain = ain.getNext();
		}
		return true;
	}

	public static boolean callsMethod(InsnList il) {
		AbstractInsnNode ain = il.getFirst();
		while (ain != null) {
			if (ain instanceof MethodInsnNode) {
				return true;
			}
			ain = ain.getNext();
		}
		return false;
	}

	public static boolean callsField(InsnList il) {
		AbstractInsnNode ain = il.getFirst();
		while (ain != null) {
			if (ain instanceof MethodInsnNode) {
				return true;
			}
			ain = ain.getNext();
		}
		return false;
	}

	public static boolean callsRef(InsnList il) {
		AbstractInsnNode ain = il.getFirst();
		while (ain != null) {
			if (ain instanceof MethodInsnNode || ain instanceof FieldInsnNode) {
				return true;
			}
			ain = ain.getNext();
		}
		return false;
	}

	public static boolean containsOpcode(InsnList il, int... opcodes) {
		AbstractInsnNode ain = il.getFirst();
		while (ain != null) {
			final int op = ain.getOpcode();
			if (Arrays.stream(opcodes).anyMatch(i -> i == op)) {
				return true;
			}
			ain = ain.getNext();
		}
		return false;
	}

	public static AbstractInsnNode findFirst(InsnList il, int op) {
		AbstractInsnNode ain = il.getFirst();
		while (ain != null) {
			if (ain.getOpcode() == op) {
				return ain;
			}
			ain = ain.getNext();
		}
		return null;
	}

	public static AbstractInsnNode findLast(InsnList il, int op) {
		AbstractInsnNode ain = il.getLast();
		while (ain != null) {
			if (ain.getOpcode() == op) {
				return ain;
			}
			ain = ain.getPrevious();
		}
		return null;
	}

	public static boolean endsRoutine(AbstractInsnNode ain) {
		int op = ain.getOpcode();
		return (op >= IFEQ && op <= RETURN) || op == ATHROW || op >= IFNULL && op <= IFNONNULL;
	}
	
	public static boolean isNumber(AbstractInsnNode ain) {
		if (ain.getOpcode() == BIPUSH || ain.getOpcode() == SIPUSH) {
			return true;
		}
		if (ain.getOpcode() >= ICONST_M1 && ain.getOpcode() <= ICONST_5) {
			return true;
		}
		if (ain instanceof LdcInsnNode) {
			LdcInsnNode ldc = (LdcInsnNode) ain;
			if (ldc.cst instanceof Number) {
				return true;
			}
		}
		return false;
	}

	public static AbstractInsnNode generateIntPush(int i) {
		if (i <= 5 && i >= -1) {
			return new InsnNode(i + 3); //iconst_i
		}
		if (i >= -128 && i <= 127) {
			return new IntInsnNode(BIPUSH, i);
		}

		if (i >= -32768 && i <= 32767) {
			return new IntInsnNode(SIPUSH, i);
		}
		return new LdcInsnNode(i);
	}

	public static int getIntValue(AbstractInsnNode node) {
		if (node.getOpcode() >= ICONST_M1 && node.getOpcode() <= ICONST_5) {
			return node.getOpcode() - 3;
		}
		if (node.getOpcode() == SIPUSH || node.getOpcode() == BIPUSH) {
			return ((IntInsnNode) node).operand;
		}
		if(node instanceof LdcInsnNode) {
			LdcInsnNode ldc = (LdcInsnNode) node;
			return Integer.parseInt(ldc.cst.toString());
		}
		return 0;
	}

	public static String getStringValue(AbstractInsnNode node) {
		if (node.getType() == AbstractInsnNode.LDC_INSN) {
			LdcInsnNode ldc = (LdcInsnNode) node;
			return ldc.cst.toString();
		}
		return "";
	}
}
