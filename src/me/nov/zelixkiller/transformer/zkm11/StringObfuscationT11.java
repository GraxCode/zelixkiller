package me.nov.zelixkiller.transformer.zkm11;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.logging.Level;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;

import me.lpk.analysis.Sandbox;
import me.lpk.util.ASMUtils;
import me.nov.zelixkiller.JarArchive;
import me.nov.zelixkiller.ZelixKiller;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.transformer.zkm11.utils.ClinitCutter;
import me.nov.zelixkiller.utils.InsnUtils;
import me.nov.zelixkiller.utils.IssueUtils;
import me.nov.zelixkiller.utils.MethodUtils;
import me.nov.zelixkiller.utils.analysis.ConstantTracker;
import me.nov.zelixkiller.utils.analysis.ConstantTracker.ConstantValue;

/**
 * Old ZKM String Obfuscation technique that is still used in some cases
 */
public class StringObfuscationT11 extends Transformer {

	private boolean invokedynamicWarn;

	@Override
	public boolean isAffected(ClassNode cn) {
		if (cn.methods.isEmpty()) {
			return false;
		}
		MethodNode staticInitializer = cn.methods.stream().filter(mn -> mn.name.equals("<clinit>")).findFirst()
				.orElse(null);
		return staticInitializer != null && containsEncryptedLDC(staticInitializer);
	}

	/**
	 * Ensure it has zkm parts in it
	 */
	public static boolean containsEncryptedLDC(MethodNode clinit) {
		for (AbstractInsnNode ain : clinit.instructions.toArray()) {
			if (ain.getOpcode() == LDC) {
				String cst = String.valueOf(((LdcInsnNode) ain).cst);
				if (cst.length() < 5)
					continue;
				// calculate standard deviation
				double sum = 0;
				char[] ccst = cst.toCharArray();
				for (char c : ccst)
					sum += c;
				double mean = sum / (double) cst.length();
				double sdev = 0.0;
				for (int i = 1; i < ccst.length; i++)
					sdev += (ccst[i] - mean) * (ccst[i] - mean);
				sdev = Math.sqrt(sdev / (ccst.length - 1.0));
				if (sdev > 30) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Check for second decryption method (two / three params (int, int, int))
	 */
	private boolean hasMathMethod(ClassNode cn) {
		for (MethodNode mn : cn.methods) {
			if (InsnUtils.matches(mn.instructions, new int[] { ILOAD, ILOAD, IXOR, SIPUSH, IXOR, LDC })) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void transform(JarArchive ja, ClassNode cn) {
		MethodNode clinit = cn.methods.stream().filter(mn -> mn.name.equals("<clinit>")).findFirst().get();
		if (InsnUtils.containsOpcode(clinit.instructions, INVOKEDYNAMIC)) {
			ZelixKiller.logger.log(Level.WARNING,
					"ZKM Static Initializer contains invokedynamic calls, decrypt dynamic calls first (Class: " + cn.name + ")");
			return;
		}
		boolean mathMethod = hasMathMethod(cn); // if false, strings are only used in static initializer itself or as single field
		if (mathMethod) {
			MethodNode mm = null;
			// fix second method
			for (MethodNode mn : cn.methods) {
				if (InsnUtils.matches(mn.instructions, new int[] { ILOAD, ILOAD, IXOR, SIPUSH, IXOR, LDC })) {
					if (InsnUtils.containsOpcode(mn.instructions, INVOKEDYNAMIC)) {
						if (!invokedynamicWarn) {
							ZelixKiller.logger.log(Level.WARNING,
									"ZKM Math Method contains invokedynamic calls, decrypt dynamic calls first (Class: " + cn.name + ")");
							invokedynamicWarn = true;
						}
						continue;
					}
					mm = mn;
					break;
				}
			}
			Class<?> proxy = createProxy(mm, clinit);
			fixMathMethod(mm, clinit, cn, proxy);
		} else {
			//TODO handle arrayloads (aggressive type)
			Class<?> proxy = createProxy(null, clinit);
			for (Field f : proxy.getDeclaredFields()) {
				try {
					f.setAccessible(true);
					String s = (String) f.get(null);
					for (MethodNode mn : cn.methods) {
						for (AbstractInsnNode ain : mn.instructions.toArray()) {
							if (ain.getOpcode() == GETSTATIC) {
								FieldInsnNode fin = (FieldInsnNode) ain;
								if (fin.owner.equals(clinit.owner) && fin.name.equals(f.getName())
										&& fin.desc.equals(Type.getDescriptor(f.getType()))) {
									mn.instructions.set(fin, new LdcInsnNode(s));
								}
							}
						}

					}
					for (FieldNode fn : new ArrayList<>(cn.fields)) {
						if (fn.name.equals(f.getName()) && fn.desc.equals(Type.getDescriptor(f.getType()))) {
							cn.fields.remove(fn);
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
		// to finish everything, clean up clinit
		InsnList originalClinit = MethodUtils.copy(clinit.instructions, ClinitCutter.findEndLabel(clinit.instructions), null);
		clinit.instructions.clear();
		clinit.instructions.add(originalClinit);
		if(originalClinit.size() <= 3) {
			cn.methods.remove(clinit);
		}
	}

	@Override
	public void postTransform() {
		ZelixKiller.logger.log(Level.INFO, "ZKM String decryption finished, please clean code afterwards");
	}

	/**
	 * Creates a proxy of a class with only decryption methods in it
	 */
	private Class<?> createProxy(MethodNode mathMethod, MethodNode clinit) {
		// cut off rest of static initializer
		InsnList decryption = ClinitCutter.cutClinit(clinit.instructions);
		MethodNode emulationNode = new MethodNode(ACC_PUBLIC | ACC_STATIC, "static_init", "()V", null, null);
		emulationNode.instructions.add(decryption);
		emulationNode.maxStack = 10;
		emulationNode.maxLocals = 20;

		ClassNode proxy = new ClassNode();
		proxy.access = ACC_PUBLIC;
		proxy.version = 52;
		proxy.name = "proxy";
		proxy.superName = "java/lang/Object";
		ArrayList<String> addedFields = new ArrayList<>();
		// add fields and fix owner
		for (AbstractInsnNode ain : emulationNode.instructions.toArray()) {
			if (ain instanceof FieldInsnNode) {
				FieldInsnNode fin = (FieldInsnNode) ain;
				String id = fin.name + fin.desc;
				if (fin.owner.equals(clinit.owner) && !addedFields.contains(id)) {
					proxy.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, fin.name, fin.desc, null, null));
					fin.owner = proxy.name;
					addedFields.add(id);
				}
			}
		}

		if (mathMethod != null) {
			InsnList mmdecr = MethodUtils.copy(mathMethod.instructions, null, null);
			MethodNode mathMethodNode = new MethodNode(ACC_PUBLIC | ACC_STATIC, "math_node", mathMethod.desc, null, null);
			mathMethodNode.instructions.add(mmdecr);
			mathMethodNode.maxStack = mathMethod.maxStack;
			mathMethodNode.maxLocals = mathMethod.maxLocals;

			// fix field owner
			for (AbstractInsnNode ain : mathMethodNode.instructions.toArray()) {
				if (ain instanceof FieldInsnNode) {
					FieldInsnNode fin = (FieldInsnNode) ain;
					if (fin.owner.equals(clinit.owner)) {
						fin.owner = proxy.name;
					}
				}
			}
			proxy.methods.add(mathMethodNode);
		}
		proxy.methods.add(emulationNode);
		// regenerate frames if original file throws verify errors
		ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
		proxy.accept(cw);
		Class<?> clazz = Sandbox.load(ASMUtils.getNode(cw.toByteArray()));
		try {
			clazz.getDeclaredMethod("static_init").invoke(null, (Object[]) null);
		} catch (Exception e) {
			e.printStackTrace();
			IssueUtils.dump(new File("fault-proxy-dump" + (System.currentTimeMillis() % 100) + ".jar"), proxy);
			throw new RuntimeException("clinit decryption unsuccessful (invocation) at class " + clinit.owner);
		}

		for (Field f : clazz.getDeclaredFields()) {
			try {
				f.setAccessible(true);
				if (f.get(null) == null) {
					IssueUtils.dump(new File("fault-proxy-dump" + (System.currentTimeMillis() % 100) + ".jar"), proxy);
					throw new RuntimeException("clinit decryption unsuccessful");
				}
			} catch (Exception e) {
				throw new RuntimeException("field error");
			}
		}
		return clazz;
	}

	/**
	 * Fixes all strings in code
	 */
	@SuppressWarnings("rawtypes")
	private void fixMathMethod(MethodNode mathMethod, MethodNode clinit, ClassNode cn, Class<?> proxy) {
		Analyzer<ConstantValue> a = new Analyzer<>(new ConstantTracker());
		for (MethodNode mn : cn.methods) {
			try {
				a.analyze(cn.name, mn);
				Frame[] frames = a.getFrames();
				int nIdx = 0;
				for (AbstractInsnNode ain : mn.instructions.toArray()) {
					if (ain.getOpcode() == INVOKESTATIC) {
						MethodInsnNode min = (MethodInsnNode) ain;
						if (min.owner.equals(cn.name) && min.name.equals(mathMethod.name) && min.desc.equals(mathMethod.desc)) {
							Frame frame = frames[nIdx];
							int j = 0;
							int[] args2 = new int[3];
							for (int i = frame.getStackSize() - 1; i > frame.getStackSize() - 4; i--) {
								ConstantValue v = (ConstantValue) frame.getStack(i);
								args2[j++] = (int) v.getValue();
							}
							try {
								Method mathMethodProxy = proxy.getDeclaredMethod("math_node", int.class, int.class, int.class);
								String decoded = (String) mathMethodProxy.invoke(null, args2[2], args2[1], args2[0]);
								for (int i = 0; i < 3; i++) {
									mn.instructions.insertBefore(min, new InsnNode(POP));
								}
								mn.instructions.set(min, new LdcInsnNode(decoded));
							} catch (Exception e) {
								e.printStackTrace();
							}

						}
					}
					nIdx++;
				}
			} catch (AnalyzerException e) {
				e.printStackTrace();
			}
		}
		// to finish everything, clean up class
		ArrayList<String> decryptionFields = new ArrayList<>();
		for (Field f : proxy.getDeclaredFields()) {
			decryptionFields.add(f.getName() + "." + Type.getDescriptor(f.getType()));
		}
		for (FieldNode fn : new ArrayList<>(cn.fields)) {
			if (decryptionFields.contains(fn.name + "." + fn.desc)) {
				cn.fields.remove(fn);
			}
		}
		cn.methods.remove(mathMethod);
	}
}
