package me.nov.zelixkiller.transformer.zkm11;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandleInfo;
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
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;

import me.lpk.analysis.Sandbox.ClassDefiner;
import me.lpk.util.AccessHelper;
import me.lpk.util.JarUtils;
import me.nov.zelixkiller.JarArchive;
import me.nov.zelixkiller.ZelixKiller;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.utils.analysis.ConstantTracker;
import me.nov.zelixkiller.utils.analysis.ConstantTracker.ConstantValue;

public class ReflectionObfuscationVMT11 extends Transformer {

	private ClassDefiner vm;
	private int references = 0;

	@Override
	public boolean isAffected(ClassNode cn) {
		return !cn.methods.isEmpty();
	}

	@Override
	public void transform(JarArchive ja, ClassNode cn) {
		cn.methods.forEach(mn -> removeDynamicCalls(cn, mn));
	}

	private void removeDynamicCalls(ClassNode cn, MethodNode mn) {
		try {
			Analyzer<ConstantValue> a = new Analyzer<>(new ConstantTracker());
			a.analyze(cn.name, mn);
			Frame<ConstantValue>[] frames = a.getFrames();
			int i = 0;
			for (AbstractInsnNode ain : mn.instructions.toArray()) {
				Frame<ConstantValue> frame = frames[i++];
				if (ain.getOpcode() == INVOKEDYNAMIC) {
					InvokeDynamicInsnNode idin = (InvokeDynamicInsnNode) ain;
					if (idin.bsm != null
							&& idin.bsm.getDesc().equals(
									"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")
							&& idin.name.length() == 1) {
						Class<?> decryptionClass = Class.forName(idin.bsm.getOwner().replace('/', '.'), true, vm);
						for (Method m : decryptionClass.getDeclaredMethods()) {
							if (m.getName().equals(idin.bsm.getName())) {
								if (m.getReturnType() == MethodHandle.class) {
									MethodType mt = MethodType.fromMethodDescriptorString(idin.desc, vm);
									MutableCallSite cs = new MutableCallSite(mt);
									long longValue = (long) frame.getStack(frame.getStackSize() - 1).getValue();
									Lookup lookup = getLookup(Class.forName(cn.name.replace('/', '.'), false, vm));
									// emulate invokedynamic to retrieve callsite
									MethodHandle mh = (MethodHandle) m.invoke(null, lookup, cs, idin.name, mt, longValue);
									if (idin.getPrevious().getOpcode() == LDC) {
										mn.instructions.remove(idin.getPrevious());
									} else {
										mn.instructions.insertBefore(idin, new InsnNode(POP2));
									}
									mn.instructions.set(idin, getOriginalNode(mh, lookup));
									references++;
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
	 */
	private AbstractInsnNode getOriginalNode(MethodHandle mh, Lookup lookup) throws Exception {
		Field original = mh.getClass().getDeclaredField("argL0");
		original.setAccessible(true);
		MethodHandle originalHandle = (MethodHandle) original.get(mh);
		//TODO fix java.lang.IllegalAccessException: class is not public
		MethodHandleInfo direct = lookup.revealDirect(originalHandle);
		int op = -1;
		if (direct.getReferenceKind() <= 4) {
			switch (direct.getReferenceKind()) {
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
			return new FieldInsnNode(op, direct.getDeclaringClass().getName().replace('.', '/'), direct.getName(),
					direct.getMethodType().toMethodDescriptorString().substring(2));
		}
		switch (direct.getReferenceKind()) {
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
		return new MethodInsnNode(op, direct.getDeclaringClass().getName().replace('.', '/'), direct.getName(),
				direct.getMethodType().toMethodDescriptorString());

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
				"Removed " + references + " invokedynamic references, please clean code afterwards");
	}

	@Override
	public void preTransform(JarArchive ja) {
		ClassNode referenceHolder = null;
		for (ClassNode cn : ja.getClasses().values()) {
			for (MethodNode mn : cn.methods) {
				for (AbstractInsnNode ain : mn.instructions.toArray()) {
					if (ain.getOpcode() == INVOKEDYNAMIC) {
						InvokeDynamicInsnNode idin = (InvokeDynamicInsnNode) ain;
						if (idin.bsm != null
								&& idin.bsm.getDesc().equals(
										"(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;")
								&& idin.name.length() == 1) {
							referenceHolder = ja.getClasses().get(idin.bsm.getOwner());
							break;
						}
					}
				}
			}
		}
		if (referenceHolder == null) {
			throw new RuntimeException("Class not obfuscated with zkm 11");
		}
		// prepare jar copy for vm
		HashMap<ClassNode, byte[]> jarCopy = new HashMap<>();
		for (ClassNode cn : ja.getClasses().values()) {
			if (!AccessHelper.isPublic(cn.access)) {
				if (AccessHelper.isPrivate(cn.access)) {
					cn.access -= ACC_PRIVATE;
				}
				if (AccessHelper.isProtected(cn.access)) {
					cn.access -= ACC_PROTECTED;
				}
				cn.access += ACC_PUBLIC;
			}
			if (!cn.equals(referenceHolder)) {
				for (MethodNode mn : cn.methods) {
					if (mn.name.equals("<clinit>")) {
						mn.tryCatchBlocks.clear();
						mn.localVariables.clear();
						mn.instructions.clear();
						mn.instructions.add(new InsnNode(RETURN));
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
