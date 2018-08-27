package me.nov.zelixkiller.transformer.zkm11;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.logging.Level;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;

import me.lpk.analysis.Sandbox.ClassDefiner;
import me.nov.zelixkiller.JarArchive;
import me.nov.zelixkiller.ZelixKiller;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.utils.ClassUtils;
import me.nov.zelixkiller.utils.InsnUtils;
import me.nov.zelixkiller.utils.IssueUtils;
import me.nov.zelixkiller.utils.MethodUtils;
import me.nov.zelixkiller.utils.analysis.ConstantTracker;
import me.nov.zelixkiller.utils.analysis.ConstantTracker.ConstantValue;

/**
 * ZKM String Obfuscation technique that uses DES
 */
public class StringObfuscationCipherT11 extends Transformer {

	public int success = 0;
	public int failure = 0;

	@Override
	public boolean isAffected(ClassNode cn) {
		if (cn.methods.isEmpty()) {
			return false;
		}
		MethodNode staticInitializer = cn.methods.stream().filter(mn -> mn.name.equals("<clinit>")).findFirst()
				.orElse(null);
		return staticInitializer != null && StringObfuscationT11.containsEncryptedLDC(staticInitializer)
				&& containsDESPadLDC(staticInitializer);
	}

	public static boolean containsDESPadLDC(MethodNode clinit) {
		for (AbstractInsnNode ain : clinit.instructions.toArray()) {
			if (ain.getOpcode() == LDC) {
				String cst = String.valueOf(((LdcInsnNode) ain).cst);
				if (cst.equals("DES/CBC/PKCS5Padding")) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public void transform(JarArchive ja, ClassNode cn) {
		MethodNode clinit = cn.methods.stream().filter(mn -> mn.name.equals("<clinit>")).findFirst().get();
		MethodNode mathMethod = findMathMethod(cn);
		Class<?> proxy = null;
		try {
			proxy = createProxy(ja, cn, clinit, mathMethod);
		} catch (Throwable t) {
			failure++;
			// TODO fix Given final block not properly padded
			return;
		}
		if (mathMethod != null) {
			replaceInvokedynamicCalls(proxy, cn, mathMethod);
		} else {
			// TODO replace fields
		}
		// TODO remove
		success++;
	}

	@SuppressWarnings("rawtypes")
	private void replaceInvokedynamicCalls(Class<?> proxy, ClassNode cn, MethodNode mathMethod) {
		for (MethodNode mn : cn.methods) {
			try {
				HashMap<AbstractInsnNode, String> decryptedStringMap = new HashMap<>();
				int nIdx = 0;
				for (AbstractInsnNode ain : mn.instructions.toArray()) {
					if (ain.getOpcode() == GETSTATIC) {
						FieldInsnNode fin = (FieldInsnNode) ain;
						if (fin.owner.equals(cn.name) && fin.desc.equals("J")) {
							try {
								Field f = proxy.getDeclaredField(fin.name);
								if (f != null && f.getType() == long.class) {
									mn.instructions.set(fin, new LdcInsnNode((long) f.get(null)));
								}
							} catch (Exception e) {
								e.printStackTrace();
							}
						}
					} else if (ain.getOpcode() == INVOKEDYNAMIC) {
						InvokeDynamicInsnNode idyn = (InvokeDynamicInsnNode) ain;
						if (idyn.desc.equals("(IJ)Ljava/lang/String;") && idyn.bsm != null && idyn.bsm.getOwner().equals(cn.name)
								&& idyn.bsm.getDesc().equals(
										"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")) {
							Analyzer<ConstantValue> a = new Analyzer<>(new ConstantTracker());
							a.analyze(cn.name, mn);
							Frame[] frames = a.getFrames();
							Frame frame = frames[nIdx];
							int j = 0;
							Object[] args = new Object[2];
							for (int i = frame.getStackSize() - 1; i > frame.getStackSize() - 3; i--) {
								ConstantValue v = (ConstantValue) frame.getStack(i);
								if (v != null)
									args[j++] = v.getValue();
							}
							for (Method m : proxy.getDeclaredMethods()) {
								if (m.getName().equals(mathMethod.name) && m.getReturnType() == String.class
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

	private MethodNode findMathMethod(ClassNode cn) {
		return cn.methods.stream()
				.filter(mn -> mn.desc.equals("(IJ)Ljava/lang/String;") && !mn.name.startsWith("<") && containsDESPadLDC(mn))
				.findFirst().orElse(null);
	}

	private Class<?> createProxy(JarArchive ja, ClassNode cn, MethodNode clinit, MethodNode mathMethod) {
		// cut off rest of static initializer
		AbstractInsnNode ret = InsnUtils.findFirst(clinit.instructions, RETURN);

		// TODO better way to find cut by getting if_icmpge label
		while (ret != null) {
			if (ret.getNext() instanceof FrameNode && ret instanceof LabelNode
					&& ((ret.getPrevious().getOpcode() == TABLESWITCH)
							|| (ret.getPrevious().getOpcode() == GOTO && ret.getPrevious().getPrevious().getOpcode() == POP))) {
				break;
			}
			ret = ret.getPrevious();
		}
		InsnList decryption = MethodUtils.copy(clinit.instructions, null, ret.getNext());
		decryption.add(new InsnNode(RETURN));
		MethodNode emulationNode = new MethodNode(ACC_PUBLIC | ACC_STATIC, "static_init", "()V", null, null);
		emulationNode.instructions.add(decryption);
		emulationNode.maxStack = 10;
		emulationNode.maxLocals = 20;

		ClassNode proxy = new ClassNode();
		proxy.access = ACC_PUBLIC;
		proxy.version = 52;
		proxy.name = "proxy"; // does this need the actual class name?
		proxy.superName = "java/lang/Object";
		ArrayList<String> addedFields = new ArrayList<>();
		ArrayList<ClassNode> decryptionClasses = new ArrayList<>();
		// add fields and fix owner
		for (AbstractInsnNode ain : emulationNode.instructions.toArray()) {
			if (ain instanceof FieldInsnNode) {
				FieldInsnNode fin = (FieldInsnNode) ain;
				String id = fin.name + fin.desc;
				if (fin.owner.equals(cn.name)) {
					fin.owner = proxy.name;
					if (!addedFields.contains(id)) {
						proxy.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, fin.name, fin.desc, null, null));
						addedFields.add(id);
					}
				}
			}
			if (ain instanceof MethodInsnNode) {
				MethodInsnNode min = (MethodInsnNode) ain;
				if (min.owner.equals(cn.name)) {
					min.owner = proxy.name;
					// we do not need to check this method
					if (ClassUtils.getMethod(proxy, min.name, min.desc) == null && !min.name.startsWith("<")) {
						proxy.methods.add(MethodUtils.cloneInstructions(ClassUtils.getMethod(cn, min.name, min.desc)));
					}
				}
			}
		}
		findBelongingClasses(new ArrayList<>(), decryptionClasses, ja, cn, proxy, emulationNode);
		proxy.methods.add(emulationNode);
		if (mathMethod != null) {
			MethodNode mathMethodClone = MethodUtils.cloneInstructions(mathMethod);
			for (AbstractInsnNode ain : mathMethodClone.instructions.toArray()) {
				if (ain instanceof FieldInsnNode) {
					FieldInsnNode fin = (FieldInsnNode) ain;
					String id = fin.name + fin.desc;
					if (fin.owner.equals(cn.name)) {
						fin.owner = proxy.name;
						if (!addedFields.contains(id)) {
							proxy.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, fin.name, fin.desc, null, null));
							addedFields.add(id);
						}
					}
				}
				if (ain instanceof MethodInsnNode) {
					MethodInsnNode min = (MethodInsnNode) ain;
					if (min.owner.equals(cn.name)) {
						min.owner = proxy.name;
						// we do not need to check this method
						if (ClassUtils.getMethod(proxy, min.name, min.desc) == null && !min.name.startsWith("<")) {
							proxy.methods.add(MethodUtils.cloneInstructions(ClassUtils.getMethod(cn, min.name, min.desc)));
						}
					}
				}
			}
			proxy.methods.add(mathMethodClone);
		}
		// regenerate frames if original file throws verify errors
		ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES) {
			protected String getCommonSuperClass(final String type1, final String type2) {
				try {
					return super.getCommonSuperClass(type1, type2);
				} catch (Throwable t) {
					return "java/lang/Object";
				}
			}
		};
		proxy.accept(cw);
		ClassDefiner vm = new ClassDefiner(ClassLoader.getSystemClassLoader());
		Class<?> clazz = vm.get(proxy.name.replace("/", "."), cw.toByteArray());

		for (ClassNode decryptionClazz : decryptionClasses) {
			ClassWriter cw2 = new ClassWriter(0);
			decryptionClazz.accept(cw2);
			vm.predefine(decryptionClazz.name.replace("/", "."), cw2.toByteArray());
		}
		try {
			clazz.getDeclaredMethod("static_init").invoke(null, (Object[]) null);
		} catch (Throwable e) {
			IssueUtils.dump(new File("fault-proxy-dump" + (System.currentTimeMillis() % 100) + ".jar"), proxy);
			throw new RuntimeException("clinit DES decryption unsuccessful (invocation) at class " + clinit.owner, e);
		}

		for (Field f : clazz.getDeclaredFields()) {
			try {
				f.setAccessible(true);
				if (f.get(null) == null) {
					IssueUtils.dump(new File("fault-proxy-dump" + (System.currentTimeMillis() % 100) + ".jar"), proxy);
					throw new RuntimeException("clinit decryption unsuccessful");
				}
			} catch (Exception e) {
				throw new RuntimeException("field error", e);
			}
		}
		IssueUtils.dump(new File("proxy-dump.jar"), proxy);
		return clazz;
	}

	private void findBelongingClasses(ArrayList<MethodNode> scanned, ArrayList<ClassNode> decryptionClasses,
			JarArchive ja, ClassNode cn, ClassNode proxy, MethodNode node) {
		if (scanned.contains(node)) {
			return;
		}
		scanned.add(node);
		for (AbstractInsnNode ain : node.instructions.toArray()) {
			if (ain instanceof MethodInsnNode) {
				MethodInsnNode min = (MethodInsnNode) ain;
				if (!min.owner.startsWith("java/") && !min.owner.startsWith("javax/")) {
					ClassNode decryptionClass = ja.getClasses().get(min.owner);
					if (decryptionClass != null && !decryptionClasses.contains(decryptionClass)) {
						decryptionClasses.add(decryptionClass);
						for (MethodNode mn : decryptionClass.methods) {
							findBelongingClasses(scanned, decryptionClasses, ja, decryptionClass, proxy, mn);
						}
					}
				}
			}
		}
	}

	@Override
	public void postTransform() {
		ZelixKiller.logger.log(Level.INFO, "Succeeded in " + success + " classes, failed in " + failure);
	}
}
