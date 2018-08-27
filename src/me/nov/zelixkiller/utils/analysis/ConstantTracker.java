package me.nov.zelixkiller.utils.analysis;

import static org.objectweb.asm.Opcodes.*;
import java.util.List;
import java.util.Objects;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;

/**
 * @author Holger https://stackoverflow.com/users/2711488/holger (Modified version)
 */
public class ConstantTracker extends Interpreter<ConstantTracker.ConstantValue> {
	static final ConstantValue NULL = new ConstantValue(BasicValue.REFERENCE_VALUE, null);

	public static final class ConstantValue implements Value {
		final Object value; // null if unknown or NULL
		final BasicValue type;

		ConstantValue(BasicValue type, Object value) {
			this.value = value;
			this.type = Objects.requireNonNull(type);
		}

		@Override
		public int getSize() {
			return type.getSize();
		}

		@Override
		public String toString() {
			Type t = type.getType();
			if (t == null)
				return "uninitialized";
			String typeName = type == BasicValue.REFERENCE_VALUE ? "a reference type" : t.getClassName();
			return this == NULL ? "null" : value == null ? "unknown value of " + typeName : value + " (" + typeName + ")";
		}

		public Object getValue() {
			return value;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (this == NULL || obj == NULL || !(obj instanceof ConstantValue))
				return false;
			ConstantValue that = (ConstantValue) obj;
			return Objects.equals(this.value, that.value) && Objects.equals(this.type, that.type);
		}

		@Override
		public int hashCode() {
			if (this == NULL)
				return ~0;
			return (value == null ? 7 : value.hashCode()) + type.hashCode() * 31;
		}
	}

	BasicInterpreter basic = new BasicInterpreter() {
		@Override
		public BasicValue newValue(Type type) {
			return type != null && (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) ? new BasicValue(type)
					: super.newValue(type);
		}

		@Override
		public BasicValue merge(BasicValue a, BasicValue b) {
			if (a.equals(b))
				return a;
			if (a.isReference() && b.isReference())
				// this is the place to consider the actual type hierarchy if you want
				return BasicValue.REFERENCE_VALUE;
			return BasicValue.UNINITIALIZED_VALUE;
		}
	};

	public ConstantTracker() {
		super(ASM5);
	}

	@Override
	public ConstantValue newOperation(AbstractInsnNode insn) throws AnalyzerException {
		switch (insn.getOpcode()) {
		case ACONST_NULL:
			return NULL;
		case ICONST_M1:
		case ICONST_0:
		case ICONST_1:
		case ICONST_2:
		case ICONST_3:
		case ICONST_4:
		case ICONST_5:
			return new ConstantValue(BasicValue.INT_VALUE, insn.getOpcode() - ICONST_0);
		case LCONST_0:
		case LCONST_1:
			return new ConstantValue(BasicValue.LONG_VALUE, (long) (insn.getOpcode() - LCONST_0));
		case FCONST_0:
		case FCONST_1:
		case FCONST_2:
			return new ConstantValue(BasicValue.FLOAT_VALUE, (float) (insn.getOpcode() - FCONST_0));
		case DCONST_0:
		case DCONST_1:
			return new ConstantValue(BasicValue.DOUBLE_VALUE, (double) (insn.getOpcode() - DCONST_0));
		case BIPUSH:
		case SIPUSH:
			return new ConstantValue(BasicValue.INT_VALUE, ((IntInsnNode) insn).operand);
		case LDC:
			return new ConstantValue(basic.newOperation(insn), ((LdcInsnNode) insn).cst);
		default:
			BasicValue v = basic.newOperation(insn);
			return v == null ? null : new ConstantValue(v, null);
		}
	}

	@Override
	public ConstantValue copyOperation(AbstractInsnNode insn, ConstantValue value) {
		return value;
	}

	@Override
	public ConstantValue newValue(Type type) {
		BasicValue v = basic.newValue(type);
		return v == null ? null : new ConstantValue(v, null);
	}

	@Override
	public ConstantValue unaryOperation(AbstractInsnNode insn, ConstantValue value) throws AnalyzerException {
		BasicValue v = basic.unaryOperation(insn, value.type);
		return v == null ? null : new ConstantValue(v, getUnaryValue(insn.getOpcode(), value.value));
	}

	private Object getUnaryValue(int opcode, Object value) {
		Number numVal = null;
		if (value instanceof Number) {
			numVal = (Number) value;
		}
		try {
			switch (opcode) {
			case INEG:
				return -((int) value);
			case FNEG:
				return -((float) value);
			case LNEG:
				return -((long) value);
			case DNEG:
				return -((double) value);
			case L2I:
			case F2I:
			case D2I:
				return numVal.intValue();
			case I2B:
				return numVal.byteValue();
			case I2C:
				return numVal.intValue() & 0x0000FFFF;
			case I2S:
				return numVal.shortValue();
			case I2F:
			case L2F:
			case D2F:
				return numVal.floatValue();
			case I2L:
			case F2L:
			case D2L:
				return numVal.longValue();
			case I2D:
			case L2D:
			case F2D:
				return numVal.doubleValue();
			case CHECKCAST:
				return value;
			default:
				return null;
			}
		} catch (NullPointerException e) {
			return null;
		}
	}

	@Override
	public ConstantValue binaryOperation(AbstractInsnNode insn, ConstantValue a, ConstantValue b)
			throws AnalyzerException {
		BasicValue v = basic.binaryOperation(insn, a.type, b.type);
		return v == null ? null : new ConstantValue(v, getBinaryValue(insn.getOpcode(), a.value, b.value));
	}

	private Object getBinaryValue(int opcode, Object a, Object b) {
		if (a == null || b == null) {
			return null;
		}
		if (!(a instanceof Number) || !(b instanceof Number)) {
			return null;
		}
		// array load instructions not handled
		Number num1 = (Number) a;
		Number num2 = (Number) b;
		switch (opcode) {
		case IADD:
			return num1.intValue() + num2.intValue();
		case ISUB:
			return num1.intValue() - num2.intValue();
		case IMUL:
			return num1.intValue() * num2.intValue();
		case IDIV:
			return num1.intValue() / num2.intValue();
		case IREM:
			return num1.intValue() % num2.intValue();
		case ISHL:
			return num1.intValue() << num2.intValue();
		case ISHR:
			return num1.intValue() >> num2.intValue();
		case IUSHR:
			return num1.intValue() >>> num2.intValue();
		case IAND:
			return num1.intValue() & num2.intValue();
		case IOR:
			return num1.intValue() | num2.intValue();
		case IXOR:
			return num1.intValue() ^ num2.intValue();
		case FADD:
			return num1.floatValue() + num2.floatValue();
		case FSUB:
			return num1.floatValue() - num2.floatValue();
		case FMUL:
			return num1.floatValue() * num2.floatValue();
		case FDIV:
			return num1.floatValue() / num2.floatValue();
		case FREM:
			return num1.floatValue() % num2.floatValue();
		case LADD:
			return num1.longValue() + num2.longValue();
		case LSUB:
			return num1.longValue() - num2.longValue();
		case LMUL:
			return num1.longValue() * num2.longValue();
		case LDIV:
			return num1.longValue() / num2.longValue();
		case LREM:
			return num1.longValue() % num2.longValue();
		case LSHL:
			return num1.longValue() << num2.longValue();
		case LSHR:
			return num1.longValue() >> num2.longValue();
		case LUSHR:
			return num1.longValue() >>> num2.longValue();
		case LAND:
			return num1.longValue() & num2.longValue();
		case LOR:
			return num1.longValue() | num2.longValue();
		case LXOR:
			return num1.longValue() ^ num2.longValue();
		case DADD:
			return num1.doubleValue() + num2.doubleValue();
		case DSUB:
			return num1.doubleValue() - num2.doubleValue();
		case DMUL:
			return num1.doubleValue() * num2.doubleValue();
		case DDIV:
			return num1.doubleValue() / num2.doubleValue();
		case DREM:
			return num1.doubleValue() % num2.doubleValue();

		// compare instructions not tested, could return wrong result
		case LCMP:
			return Long.compare(num1.longValue(), num2.longValue());
		case FCMPL:
		case FCMPG:
			// no NaN handling, could affect results
			return Float.compare(num1.longValue(), num2.longValue());
		case DCMPL:
		case DCMPG:
			// no NaN handling, could affect results
			return Double.compare(num1.longValue(), num2.longValue());
		default:
			return null;
		}
	}

	@Override
	public ConstantValue ternaryOperation(AbstractInsnNode insn, ConstantValue a, ConstantValue b, ConstantValue c) {
		return null;
	}

	@Override
	public ConstantValue naryOperation(AbstractInsnNode insn, List<? extends ConstantValue> values)
			throws AnalyzerException {
		List<BasicValue> unusedByBasicInterpreter = null;
		BasicValue v = basic.naryOperation(insn, unusedByBasicInterpreter);
		return v == null ? null : new ConstantValue(v, null);
	}

	@Override
	public void returnOperation(AbstractInsnNode insn, ConstantValue value, ConstantValue expected) {
	}

	@Override
	public ConstantValue merge(ConstantValue a, ConstantValue b) {
		if (a.equals(b))
			return a;
		BasicValue t = basic.merge(a.type, b.type);
		if ((a == null) || (a == null) || t == null)
			System.out.println((a != null) + " " + (b != null));
		return t.equals(a.type) && (a.value == null && a != NULL || a.value != null && a.value.equals(b.value)) ? a
				: t.equals(b.type) && b.value == null && b != NULL ? b : new ConstantValue(t, null);
	}
}