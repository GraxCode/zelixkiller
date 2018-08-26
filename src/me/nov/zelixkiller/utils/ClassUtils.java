package me.nov.zelixkiller.utils;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public class ClassUtils {
	public static MethodNode getMethod(ClassNode cn, String name) {
		for (MethodNode mn : cn.methods) {
			if (mn.name.equals(name)) {
				return mn;
			}
		}
		return null;
	}

	public static MethodNode getMethod(ClassNode cn, String name, String desc) {
		for (MethodNode mn : cn.methods) {
			if (mn.name.equals(name) && mn.desc.equals(desc)) {
				return mn;
			}
		}
		return null;
	}
}
