package me.nov.zelixkiller.utils;

import java.io.File;
import java.util.HashMap;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import me.lpk.util.JarUtils;

public class IssueUtils {
	public static void dump(File output, ClassNode... cns) {
		HashMap<String, byte[]> file = new HashMap<>();
		for (ClassNode cn : cns) {
			ClassWriter cw = new ClassWriter(0);
			cn.accept(cw);
			file.put(cn.name, cw.toByteArray());
		}
		JarUtils.saveAsJar(file, output);
	}
}
