package me.nov.zelixkiller.transformer.zkm11;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.invoke.MethodType;
import java.lang.invoke.MutableCallSite;
import java.lang.reflect.Constructor;
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
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;

import me.lpk.analysis.Sandbox.ClassDefiner;
import me.lpk.util.AccessHelper;
import me.nov.zelixkiller.JarArchive;
import me.nov.zelixkiller.ZelixKiller;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.utils.ClassUtils;
import me.nov.zelixkiller.utils.ReflectionUtils;
import me.nov.zelixkiller.utils.analysis.ConstantTracker;
import me.nov.zelixkiller.utils.analysis.ConstantTracker.ConstantValue;

public class ReflectionObfuscationVMT11 extends Transformer {

	private ClassDefiner vm;
	private int reversed = 0;
	private boolean twoLongType;
	private int references;

	@Override
	public boolean isAffected(ClassNode cn) {
		return !cn.methods.isEmpty();
	}

	@Override
	public void transform(JarArchive ja, ClassNode node) {
		if (twoLongType) {
			// init surroundings before decryption
			Outer: for (ClassNode cn : ja.getClasses().values()) {
				for (MethodNode mn : cn.methods) {
					for (AbstractInsnNode ain : mn.instructions.toArray()) {
						if (ain.getOpcode() == INVOKESPECIAL) {
							MethodInsnNode min = (MethodInsnNode) ain;
							if (min.owner.equals(node.name) && min.name.equals("<init>")) {
								try {
									Class.forName(cn.name.replace("/", "."), true, vm);
								} catch (ClassNotFoundException e) {
								}
								continue Outer;
							}
						}
					}
				}
			}
		}
		node.methods.forEach(mn -> removeDynamicCalls(node, mn));
	}

	private void removeDynamicCalls(ClassNode cn, MethodNode mn) {
		if (twoLongType) {
			for (AbstractInsnNode ain : mn.instructions.toArray()) {
				if (ain.getOpcode() == GETSTATIC) {
					FieldInsnNode fin = (FieldInsnNode) ain;
					if (fin.owner.equals(cn.name) && fin.desc.equals("J")) {
						// inline needed fields
						try {
							Field f = Class.forName(cn.name.replace('/', '.'), true, vm).getDeclaredField(fin.name);
							if (f != null && f.getType() == long.class) {
								f.setAccessible(true);
								long l = (long) f.get(null);
								if (l != 0) {
									mn.instructions.set(fin, new LdcInsnNode(l));
								}
							}
						} catch (Exception e) {
							ZelixKiller.logger.log(Level.SEVERE, "Exception at inlining field", e);
							continue;
						}
					}
				}
			}
		}
		try {
			int i = -1;
			Analyzer<ConstantValue> a = new Analyzer<>(new ConstantTracker());
			a.analyze(cn.name, mn);
			Frame<ConstantValue>[] frames = a.getFrames();
			for (AbstractInsnNode ain : mn.instructions.toArray()) {
				i++;
				if (ain.getOpcode() == INVOKEDYNAMIC) {
					InvokeDynamicInsnNode idin = (InvokeDynamicInsnNode) ain;
					if (idin.bsm != null
							&& idin.bsm.getDesc().equals(
									"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")
							&& idin.name.length() == 1) {
						references++;
						Class<?> decryptionClass = Class.forName(idin.bsm.getOwner().replace('/', '.'), true, vm);
						for (Method m : decryptionClass.getDeclaredMethods()) {
							if (m.getName().equals(idin.bsm.getName())) {
								if (m.getReturnType() == MethodHandle.class) {
									Frame<ConstantValue> frame = frames[i];
									MethodType mt = MethodType.fromMethodDescriptorString(idin.desc, vm);
									MutableCallSite cs = new MutableCallSite(mt);
									if (twoLongType) {
										long longValue = 0;
										long secondLongValue = 0;
										try {
											longValue = (long) frame.getStack(frame.getStackSize() - 2).getValue();
											secondLongValue = (long) frame.getStack(frame.getStackSize() - 1).getValue();
										} catch (NullPointerException e) {
											ZelixKiller.logger.log(Level.FINE,
													"Couldn't resolve both long values in class " + cn.name + ", skipping!");
											return;
										}
										Lookup lookup = getLookup(Class.forName(cn.name.replace('/', '.'), true, vm));
										ReflectionUtils.setFinal(lookup.getClass().getDeclaredField("allowedModes"), lookup, -1); //trust lookup
										// emulate invokedynamic to retrieve callsite
										MethodHandle mh = (MethodHandle) m.invoke(null, lookup, cs, idin.name, mt, longValue,
												secondLongValue);
										AbstractInsnNode original = getOriginalNode(mh, lookup);
										if (idin.getPrevious().getPrevious().getOpcode() == LDC
												&& idin.getPrevious().getOpcode() == LLOAD) {
											mn.instructions.remove(idin.getPrevious().getPrevious());
											mn.instructions.remove(idin.getPrevious());
										} else {
											mn.instructions.insertBefore(idin, new InsnNode(POP2));
											mn.instructions.insertBefore(idin, new InsnNode(POP2));
										}
										mn.instructions.set(idin, original);
										reversed++;
									} else {
										long longValue = (long) frame.getStack(frame.getStackSize() - 1).getValue();
										Lookup lookup = getLookup(Class.forName(cn.name.replace('/', '.'), true, vm));
										ReflectionUtils.setFinal(lookup.getClass().getDeclaredField("allowedModes"), lookup, -1); //trust lookup
										// emulate invokedynamic to retrieve callsite
										MethodHandle mh = (MethodHandle) m.invoke(null, lookup, cs, idin.name, mt, longValue);
										AbstractInsnNode original = getOriginalNode(mh, lookup);
										if (idin.getPrevious().getOpcode() == LDC) {
											mn.instructions.remove(idin.getPrevious());
										} else {
											mn.instructions.insertBefore(idin, new InsnNode(POP2));
										}
										mn.instructions.set(idin, original);
										reversed++;
									}
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Converts BoundMethodHandle$Species_L to AbstractInsnNode reference
	 * 
	 * @param cn
	 */
	private AbstractInsnNode getOriginalNode(MethodHandle mh, Lookup lookup) throws Exception {
		Field original = mh.getClass().getDeclaredField("argL0");
		original.setAccessible(true);
		MethodHandle originalHandle = (MethodHandle) original.get(mh);

		// hack to bypass java.lang.IllegalAccessException: class is not public
		// this is basically MethodHandles.revealDirect without access restriction

		Object mn = getMemberName(originalHandle);
		Class<?> memberName = mn.getClass();
		Method getReferenceKind = memberName.getDeclaredMethod("getReferenceKind");
		getReferenceKind.setAccessible(true);
		byte refKind = (byte) getReferenceKind.invoke(mn);
		Method getDeclaringClass = memberName.getDeclaredMethod("getDeclaringClass");
		getDeclaringClass.setAccessible(true);
		Class<?> declaringClass = (Class<?>) getDeclaringClass.invoke(mn);
		Method getName = memberName.getDeclaredMethod("getName");
		getName.setAccessible(true);
		String name = (String) getName.invoke(mn);
		Method getMethodType = memberName.getDeclaredMethod("getMethodOrFieldType");
		getMethodType.setAccessible(true);
		MethodType methodType = (MethodType) getMethodType.invoke(mn);

		Method isSpecial = MethodHandle.class.getDeclaredMethod("isInvokeSpecial");
		isSpecial.setAccessible(true);
		if (refKind == 7 && !(boolean) isSpecial.invoke(originalHandle)) {
			refKind = 5;
		}
		if (refKind == 5 && declaringClass.isInterface()) {
			refKind = 9;
		}
		if(declaringClass.getName().contains("$BindCaller$T/")) {
			throw new RuntimeException("Couldn't decrypt anonymous class");
			//TODO bypass UNSAFE.defineAnonymousClass MethodHandleImpl$BindCaller
		}
		int op = -1;
		if (refKind <= 4) {
			switch (refKind) {
			case 1:
				op = GETFIELD;
				break;
			case 2:
				op = GETSTATIC;
				break;
			case 3:
				op = PUTFIELD;
				break;
			case 4:
				op = PUTSTATIC;
				break;
			}
			String desc;
			if (refKind <= 2) {
				desc = methodType.toMethodDescriptorString().substring(2);
			} else {
				// method handle treats field setting as a method (returning void)
				String mds = methodType.toMethodDescriptorString();
				desc = mds.substring(1, mds.lastIndexOf(')'));
			}
			return new FieldInsnNode(op, declaringClass.getName().replace('.', '/'), name, desc);
		}
		switch (refKind) {
		case 5:
			op = INVOKEVIRTUAL;
			break;
		case 6:
			op = INVOKESTATIC;
			break;
		case 7:
		case 8:
			op = INVOKESPECIAL;
			break;
		case 9:
			op = INVOKEINTERFACE;
			break;
		}
		return new MethodInsnNode(op, declaringClass.getName().replace('.', '/'), name,
				methodType.toMethodDescriptorString());
	}

	private Object getMemberName(MethodHandle originalHandle) throws Exception {
		Method internalMemberName = MethodHandle.class.getDeclaredMethod("internalMemberName");
		internalMemberName.setAccessible(true);
		return internalMemberName.invoke(originalHandle);
	}

	/**
	 * Creates lookup as if it was by invokedynamic
	 */
	private Lookup getLookup(Class<?> clazz) throws Exception {
		Constructor<Lookup> constructor = MethodHandles.Lookup.class.getDeclaredConstructor(Class.class);
		constructor.setAccessible(true);
		return constructor.newInstance(clazz);
	}

	@Override
	public void postTransform() {
		ZelixKiller.logger.log(Level.INFO,
				"Removed " + reversed + " invokedynamic references of " + references + ", please clean code afterwards");
	}

	@Override
	public void preTransform(JarArchive ja) {
		ClassNode referenceHolder = null;
		Outer: for (ClassNode cn : ja.getClasses().values()) {
			for (MethodNode mn : cn.methods) {
				for (AbstractInsnNode ain : mn.instructions.toArray()) {
					if (ain.getOpcode() == INVOKEDYNAMIC) {
						InvokeDynamicInsnNode idin = (InvokeDynamicInsnNode) ain;
						if (idin.bsm != null
								&& idin.bsm.getDesc().equals(
										"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")
								&& idin.name.length() == 1) {
							referenceHolder = ja.getClasses().get(idin.bsm.getOwner());
							ZelixKiller.logger.log(Level.FINE, "Found class with bootstrap method (" + referenceHolder.name + ")");
							if (idin.desc.contains("JJ)")) {
								ZelixKiller.logger.log(Level.FINE, "Bootstrap uses two long values instead of one");
								twoLongType = true;
							}
							break Outer;
						}
					}
				}
			}
		}
		if (referenceHolder == null) {
			throw new RuntimeException("Class not obfuscated with zkm 11");
		}
		ArrayList<ClassNode> associatedDecryptionClasses = StringObfuscationCipherVMT11
				.findDecryptionClasses(ja.getClasses());
		ZelixKiller.logger.log(Level.FINE,
				"Found " + associatedDecryptionClasses.size() + " associated decryption classes");
		// prepare jar copy for vm
		HashMap<ClassNode, byte[]> jarCopy = new HashMap<>();
		for (ClassNode node : ja.getClasses().values()) {
			ClassNode cn = ClassUtils.clone(node);
			if (!AccessHelper.isPublic(cn.access)) {
				if (AccessHelper.isPrivate(cn.access)) {
					cn.access -= ACC_PRIVATE;
				}
				if (AccessHelper.isProtected(cn.access)) {
					cn.access -= ACC_PROTECTED;
				}
				cn.access += ACC_PUBLIC;
			}

			// remove clinit from non decryption classes
			if (!node.equals(referenceHolder) && !associatedDecryptionClasses.contains(node)) {
				for (MethodNode mn : cn.methods) {
					if (mn.name.equals("<clinit>")) {
						mn.tryCatchBlocks.clear();
						mn.localVariables.clear();
						if (mn.instructions.size() > 8) {
							AbstractInsnNode third = mn.instructions.getFirst().getNext().getNext();
							if (third instanceof MethodInsnNode) {
								MethodInsnNode min = (MethodInsnNode) third;
								if (min.owner.equals("java/lang/invoke/MethodHandles") && min.name.equals("lookup")) {
									AbstractInsnNode ain = third;
									while (ain != null && ain.getOpcode() != INVOKEINTERFACE) {
										ain = ain.getNext();
									}
									if (ain.getNext().getOpcode() != PUTSTATIC) {
										// TODO fix long only used in clinit, causing "Couldn't resolve both long values"
										mn.instructions.insert(ain, new InsnNode(POP2));
									}
									ain = ain.getNext();
									if (ain == null) {
										// TODO
										mn.instructions.clear();
										mn.instructions.add(new InsnNode(RETURN));
										continue;
									}
									while (ain.getNext() != null) {
										mn.instructions.remove(ain.getNext());
									}
									mn.instructions.add(new InsnNode(RETURN));
								}
							}
						} else {
							mn.instructions.clear();
							mn.instructions.add(new InsnNode(RETURN));
						}
					}
				}
			}
			ClassWriter cw = new ClassWriter(0);
			cn.accept(cw);
			jarCopy.put(cn, cw.toByteArray());
		}
		vm = new ClassDefiner(ClassLoader.getSystemClassLoader());
		for (Entry<ClassNode, byte[]> e : jarCopy.entrySet()) {
			vm.predefine(e.getKey().name.replace("/", "."), e.getValue());
		}
	}
}
