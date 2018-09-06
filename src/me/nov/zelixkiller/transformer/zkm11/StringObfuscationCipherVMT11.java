package me.nov.zelixkiller.transformer.zkm11;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;

import javax.crypto.BadPaddingException;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;

import me.lpk.analysis.Sandbox.ClassDefiner;
import me.lpk.util.ASMUtils;
import me.nov.zelixkiller.JarArchive;
import me.nov.zelixkiller.ZelixKiller;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.transformer.zkm11.utils.ClinitCutter;
import me.nov.zelixkiller.utils.ClassUtils;
import me.nov.zelixkiller.utils.IssueUtils;
import me.nov.zelixkiller.utils.MethodUtils;
import me.nov.zelixkiller.utils.analysis.ConstantTracker;
import me.nov.zelixkiller.utils.analysis.ConstantTracker.ConstantValue;

/**
 * Decrypts ZKM String Obfuscation technique that uses DES Creates a VM and deobfuscates by invoking static initializer
 */
public class StringObfuscationCipherVMT11 extends Transformer {

	public int success = 0;
	public int failures = 0;
	private int inners = 0;

	@Override
	public boolean isAffected(ClassNode cn) {
		return false;
	}

	@Override
	public void transform(JarArchive ja, ClassNode cn) {
	}

	@Override
	public void preTransform(JarArchive ja) {
		ArrayList<ClassNode> dc = findDecryptionClasses(ja.getClasses());
		HashMap<ClassNode, byte[]> isolatedJarCopy = new HashMap<>();
		for (ClassNode cn : dc) {
			ClassWriter cw2 = new ClassWriter(ClassWriter.COMPUTE_MAXS);
			cn.accept(cw2);
			isolatedJarCopy.put(cn, cw2.toByteArray());
		}
		for (ClassNode cn : ja.getClasses().values()) {
			if (dc.contains(cn))
				continue;
			ClassNode proxy = createProxy(cn);
			ClassWriter cw2 = new ClassWriter(ClassWriter.COMPUTE_MAXS);
			proxy.accept(cw2);
			isolatedJarCopy.put(cn, cw2.toByteArray());
		}
		for (ClassNode cn : ja.getClasses().values()) {
			try {
				ClassDefiner vm = new ClassDefiner(ClassLoader.getSystemClassLoader());
				for (Entry<ClassNode, byte[]> e : isolatedJarCopy.entrySet()) {
					vm.predefine(e.getKey().name.replace("/", "."), e.getValue());
				}
				Class<?> clazz = Class.forName(cn.name.replace("/", "."), true, vm); // or vm.loadClass(cn.name.replace("/", ".")) which won't load superclasses
				replaceInvokedynamicCalls(clazz, cn);
				success++;
			} catch (Throwable t) {
				if (t instanceof VerifyError) {
					ZelixKiller.logger.log(Level.SEVERE, "Verify exception at loading proxy for class " + cn.name, t);
					IssueUtils.dump(new File("proxy-dump-verify-error.jar"), ASMUtils.getNode(isolatedJarCopy.get(cn)));
				} else if (t instanceof ExceptionInInitializerError && t.getCause() instanceof BadPaddingException) {
					try {
						// if the key is wrong, there may be an outer class that didn't get invoked
						treatAsInner(cn, ja.getClasses().values(), isolatedJarCopy);
						success++;
					} catch (Throwable t2) {
						ZelixKiller.logger.log(Level.SEVERE, "Exception at treating class as inner class " + cn.name, t2);
						failures++;
					}
				} else {
					ZelixKiller.logger.log(Level.SEVERE, "Exception at loading proxy for class " + cn.name, t);
					failures++;
				}

			}
		}
	}

	/**
	 * Find and decrypt outer class(es) of class first
	 */
	private void treatAsInner(ClassNode node, Collection<ClassNode> values, HashMap<ClassNode, byte[]> isolatedJarCopy)
			throws Exception {
		ClassDefiner vm = new ClassDefiner(ClassLoader.getSystemClassLoader());
		for (Entry<ClassNode, byte[]> e : isolatedJarCopy.entrySet()) {
			vm.predefine(e.getKey().name.replace("/", "."), e.getValue());
		}
		inners++;
		int surroundings = 0;
		Outer: for (ClassNode cn : values) {
			for (MethodNode mn : cn.methods) {
				for (AbstractInsnNode ain : mn.instructions.toArray()) {
					if (ain.getOpcode() == INVOKESPECIAL) {
						MethodInsnNode min = (MethodInsnNode) ain;
						if (min.owner.equals(node.name) && min.name.equals("<init>")) {
							Class.forName(cn.name.replace("/", "."), true, vm);
							surroundings++;
							continue Outer;
						}
					}
				}
			}
		}
		if (surroundings > 1) {
			ZelixKiller.logger.log(Level.WARNING,
					"Inner class " + node.name + " has multiple surroundings (" + surroundings + ")");
		}
		Class<?> clazz = Class.forName(node.name.replace("/", "."), true, vm);
		replaceInvokedynamicCalls(clazz, node);
	}

	@SuppressWarnings("deprecation")
	private ArrayList<ClassNode> findDecryptionClasses(Map<String, ClassNode> map) {
		ArrayList<ClassNode> dc = new ArrayList<>();
		Outer: for (ClassNode cn : map.values()) {
			MethodNode clinit = cn.methods.stream().filter(mn -> mn.name.equals("<clinit>")).findFirst().orElse(null);
			if (clinit != null && StringObfuscationCipherT11.containsDESPadLDC(clinit)) {
				for (AbstractInsnNode ain : clinit.instructions.toArray()) {
					if (ain instanceof MethodInsnNode) {
						MethodInsnNode min = (MethodInsnNode) ain;
						if (min.desc.startsWith("(JJLjava/lang/Object;)L")) {
							for (MethodNode mn : map.get(min.owner).methods) {
								for (ClassNode decl : findBelongingClasses(new ArrayList<>(), mn, map)) {
									if (!dc.contains(decl))
										dc.add(decl);
								}
							}
							break Outer;
						}
					}
				}
			}
		}
		return dc;
	}

	private Collection<ClassNode> findBelongingClasses(ArrayList<MethodNode> visited, MethodNode method,
			Map<String, ClassNode> map) {
		ArrayList<ClassNode> list = new ArrayList<>();
		if (visited.contains(method))
			return list;
		visited.add(method);
		for (AbstractInsnNode ain : method.instructions.toArray()) {
			if (ain instanceof MethodInsnNode) {
				MethodInsnNode min = (MethodInsnNode) ain;
				if (!min.owner.startsWith("java/") && !min.owner.startsWith("javax/")) {
					ClassNode decryptionClass = map.get(min.owner);
					if (decryptionClass != null && !list.contains(decryptionClass)) {
						list.add(decryptionClass);
						for (MethodNode mn : decryptionClass.methods) {
							for (ClassNode cn : findBelongingClasses(visited, mn, map)) {
								if (!list.contains(cn)) {
									list.add(cn);
								}
							}
						}
					}
				}

			}
		}
		return list;
	}

	private static final boolean debugClassInit = false;

	@SuppressWarnings("deprecation")
	private ClassNode createProxy(ClassNode cn) {
		ClassNode proxy = new ClassNode();
		proxy.name = cn.name;
		proxy.version = cn.version;
		proxy.superName = cn.superName;
		proxy.interfaces = cn.interfaces;
		proxy.access = cn.access;
		MethodNode clinit = cn.methods.stream().filter(mn -> mn.name.equals("<clinit>")).findFirst().orElse(null);
		if (clinit != null && StringObfuscationCipherT11.containsDESPadLDC(clinit)) {
			try {
				InsnList decryption = ClinitCutter.cutClinit(clinit);
				removeUnwantedCalls(decryption);
				MethodNode newclinit = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
				if (debugClassInit) {
					decryption
							.insert(new MethodInsnNode(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V"));
					decryption.insert(new LdcInsnNode(cn.name));
					decryption.insert(new FieldInsnNode(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;"));
				}
				newclinit.instructions.add(decryption);
				newclinit.maxStack = 10;
				newclinit.maxLocals = 20;
				proxy.methods.add(newclinit);
				ArrayList<String> neededClassContents = findNeededContents(cn, newclinit);
				for (FieldNode fn : cn.fields) {
					if (neededClassContents.contains(fn.name + fn.desc))
						proxy.fields.add(new FieldNode(fn.access, fn.name, fn.desc, fn.signature, fn.value));
				}
				for (MethodNode mn : cn.methods) {
					if (neededClassContents.contains(mn.name + mn.desc) || isInvokedynamicMethod(mn))
						proxy.methods.add(MethodUtils.cloneInstructions(mn,
								mn.name.startsWith("<") ? mn.name.replace("<", "___").replace(">", "___") : null));
				}
			} catch (Exception e) {
				e.printStackTrace();

			}
		} else if (debugClassInit) {
			InsnList decryption = new InsnList();
			MethodNode newclinit = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
			decryption.insert(new MethodInsnNode(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V"));
			decryption.insert(new LdcInsnNode(cn.name));
			decryption.insert(new FieldInsnNode(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;"));
			decryption.add(new InsnNode(RETURN));
			newclinit.instructions.add(decryption);
			proxy.methods.add(newclinit);
		}
		return proxy;
	}

	private void removeUnwantedCalls(InsnList decryption) {
		// TODO remove unwanted methodinsnnodes
		for (AbstractInsnNode ain : decryption.toArray()) {
			if (ain.getOpcode() == INVOKEDYNAMIC) {
				InvokeDynamicInsnNode idin = (InvokeDynamicInsnNode) ain;
				if (idin.desc.equals("(IJ)Ljava/lang/String;")) {
					decryption.insertBefore(idin, new InsnNode(POP2));
					decryption.insert(idin, new LdcInsnNode("<clinit> decryption invokedynamic string undecrypted"));
					decryption.set(idin, new InsnNode(POP));
				}
			}
		}
	}

	@SuppressWarnings("deprecation")
	private boolean isInvokedynamicMethod(MethodNode mn) {
		return mn.desc.equals("(IJ)Ljava/lang/String;") && StringObfuscationCipherT11.containsDESPadLDC(mn);
	}

	private ArrayList<String> findNeededContents(ClassNode cn, MethodNode mn) {
		ArrayList<String> neededContents = new ArrayList<>();
		for (AbstractInsnNode ain : mn.instructions.toArray()) {
			if (ain instanceof MethodInsnNode) {
				MethodInsnNode min = (MethodInsnNode) ain;
				if (min.owner.equals(cn.name) && !neededContents.contains(min.name + min.desc)) {
					neededContents.add(min.name + min.desc);
					neededContents.addAll(findNeededContents(cn, ClassUtils.getMethod(cn, min.name, min.desc)));
				}
			}
			if (ain instanceof FieldInsnNode) {
				FieldInsnNode fin = (FieldInsnNode) ain;
				if (fin.owner.equals(cn.name) && !neededContents.contains(fin.name + fin.desc)) {
					neededContents.add(fin.name + fin.desc);
				}
			}
		}
		return neededContents;
	}

	private void replaceInvokedynamicCalls(Class<?> proxy, ClassNode cn) {
		ArrayList<Field> singleFields = new ArrayList<>();
		for (Field f : proxy.getDeclaredFields()) {
			if (f.getType() == String.class) {
				f.setAccessible(true);
				singleFields.add(f);
			}
		}
		for (MethodNode mn : cn.methods) {
			try {
				HashMap<AbstractInsnNode, String> decryptedStringMap = new HashMap<>();
				int nIdx = 0;
				for (AbstractInsnNode ain : mn.instructions.toArray()) {
					if (ain.getOpcode() == GETSTATIC) {
						FieldInsnNode fin = (FieldInsnNode) ain;
						if (fin.owner.equals(cn.name) && fin.desc.equals("J")) {
							// inline needed fields
							try {
								Field f = proxy.getDeclaredField(fin.name);
								if (f != null && f.getType() == long.class) {
									f.setAccessible(true);
									mn.instructions.set(fin, new LdcInsnNode((long) f.get(null)));
								}
							} catch (Exception e) {
								ZelixKiller.logger.log(Level.SEVERE, "Exception at inlining field", e);
								continue;
							}
						} else if (fin.owner.equals(cn.name) && fin.desc.equals("Ljava/lang/String;")) {
							try {
								for (Field f : singleFields) {
									if (fin.name.equals(f.getName())) {
										String val = (String) f.get(null);
										if (val != null)
											mn.instructions.set(fin, new LdcInsnNode(val));
									}
								}
							} catch (Exception e) {
								ZelixKiller.logger.log(Level.SEVERE, "Exception at inlining single field", e);
								continue;
							}
						}
					} else if (ain.getOpcode() == INVOKEDYNAMIC) {
						// invokedynamic just invokes (String, long, int) method
						InvokeDynamicInsnNode idyn = (InvokeDynamicInsnNode) ain;
						if (idyn.desc.equals("(IJ)Ljava/lang/String;") && idyn.bsm != null && idyn.bsm.getOwner().equals(cn.name)
								&& idyn.bsm.getDesc().equals(
										"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")) {
							Analyzer<ConstantValue> a = new Analyzer<>(new ConstantTracker());
							a.analyze(cn.name, mn);
							Frame<ConstantValue>[] frames = a.getFrames();
							Frame<ConstantValue> frame = frames[nIdx];
							int j = 0;
							Object[] args = new Object[2];
							for (int i = frame.getStackSize() - 1; i > frame.getStackSize() - 3; i--) {
								ConstantValue v = frame.getStack(i);
								if (v != null)
									args[j++] = v.getValue();
							}
							for (Method m : proxy.getDeclaredMethods()) {
								if (m.getReturnType() == String.class && m.getParameterTypes().length == 2
										&& m.getParameterTypes()[0] == int.class && m.getParameterTypes()[1] == long.class) {
									try {
										m.setAccessible(true);
										String decrypted = (String) m.invoke(null, args[1], args[0]);
										decryptedStringMap.put(idyn, decrypted);
									} catch (Exception e) {
										throw new RuntimeException("math method threw exception", e);
									}
									break;
								}
							}
						}
					}
					nIdx++;
				}
				for (Entry<AbstractInsnNode, String> entry : decryptedStringMap.entrySet()) {
					mn.instructions.insertBefore(entry.getKey(), new InsnNode(POP2));
					mn.instructions.insertBefore(entry.getKey(), new InsnNode(POP));
					mn.instructions.set(entry.getKey(), new LdcInsnNode(entry.getValue()));
				}
			} catch (AnalyzerException e) {
				e.printStackTrace();
				continue;
			}
		}
	}

	@Override
	public void postTransform() {
		ZelixKiller.logger.log(Level.INFO,
				"Succeeded in " + success + " classes (" + inners + " inner classes), failed in " + failures);
	}
}
