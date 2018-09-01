package me.nov.zelixkiller.transformer;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import me.nov.zelixkiller.JarArchive;

public abstract class Transformer implements Opcodes {
	public abstract boolean isAffected(ClassNode cn);
	public abstract void transform(JarArchive ja, ClassNode cn);
	public abstract void preTransform(JarArchive ja);
	public abstract void postTransform();
}
