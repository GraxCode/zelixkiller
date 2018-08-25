package me.nov.zelixkiller;

import java.io.File;
import java.util.Map;

import org.objectweb.asm.tree.ClassNode;

public class JarArchive {

	private Map<String, ClassNode> classes;
	private Map<String, byte[]> out;
	private File input;

	public JarArchive(File input, Map<String, ClassNode> classes, Map<String, byte[]> out) {
		this.input = input;
		this.classes = classes;
		this.out = out;
	}

	public Map<String, ClassNode> getClasses() {
		return classes;
	}

	public Map<String, byte[]> getOut() {
		return out;
	}

	public File getInput() {
		return input;
	}

}
