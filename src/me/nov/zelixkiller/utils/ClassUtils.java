package me.nov.zelixkiller.utils;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import me.lpk.util.ASMUtils;

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
	
	public static ClassNode clone(ClassNode cn) {
		ClassWriter cw = new ClassWriter(0);
		cn.accept(cw);
		return ASMUtils.getNode(cw.toByteArray());
	}
}
