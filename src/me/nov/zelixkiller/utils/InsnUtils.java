package me.nov.zelixkiller.utils;

import java.util.Arrays;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;

public class InsnUtils {
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
}
