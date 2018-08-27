package me.nov.zelixkiller;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import me.lpk.util.JarUtils;
import me.nov.zelixkiller.transformer.Transformer;
import me.nov.zelixkiller.transformer.zkm.ExceptionObfuscationTX;
import me.nov.zelixkiller.transformer.zkm11.StringObfuscationCipherT11;
import me.nov.zelixkiller.transformer.zkm11.StringObfuscationT11;

public class ZelixKiller {
	public final static Logger logger = Logger.getLogger(ZelixKiller.class.getName());
	private final static HashMap<String, Class<? extends Transformer>> transformers = new HashMap<>();

	static {
		System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tT] [%4$-7s] %5$s %n");
		transformers.put("s11", StringObfuscationT11.class);
		transformers.put("si11", StringObfuscationCipherT11.class);
		transformers.put("ex", ExceptionObfuscationTX.class);
	}

	public static void main(String[] args) throws Exception {
		Options options = new Options();
		options.addOption("i", "input", true, "The obfuscated input file to use");
		options.addOption("o", "output", true, "The output file");
		options.addOption("t", "transformer", true, "The transformer to use");
		options.addOption("help", false, "Prints this help");

		CommandLineParser parser = new DefaultParser();
		CommandLine line;
		try {
			line = parser.parse(options, args);
		} catch (org.apache.commons.cli.ParseException e) {
			e.printStackTrace();
			throw new RuntimeException("An error occurred while parsing the commandline!");
		}
		if (line.hasOption("help") || !line.hasOption("i") || !line.hasOption("o") || !line.hasOption("t")) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("zelixkiller 11", options);
			return;
		}
		File input = new File(line.getOptionValue("i"));
		File output = new File(line.getOptionValue("o"));
		if (!input.exists()) {
			throw new FileNotFoundException(input.getAbsolutePath());
		}
		if (output.exists()) {
			logger.log(Level.INFO, "Output already exists, renaming existing file");
			File existing = new File(line.getOptionValue("o"));
			File newName = new File(line.getOptionValue("o") + "-BAK");
			if (newName.exists()) {
				newName.delete();
			}
			existing.renameTo(newName);
		}
		String transf = line.getOptionValue("t");
		if (!transformers.containsKey(transf)) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("zelixkiller 11", options);
			return;
		}
		Transformer t = transformers.get(transf).newInstance();
		Map<String, ClassNode> classes = JarUtils.loadClasses(input);
		Map<String, byte[]> out = JarUtils.loadNonClassEntries(input);
		JarArchive ja = new JarArchive(input, classes, out);
		logger.log(Level.INFO, "Starting with deobfuscation using transformer " + t.getClass().getSimpleName());
		for (ClassNode cn : new ArrayList<>(classes.values())) {
			if (t.isAffected(cn)) {
				t.transform(ja, cn);
			}
		}
		t.postTransform();
		for (ClassNode cn : classes.values()) {
			ClassWriter cw = new ClassWriter(0);
			cn.accept(cw);
			out.put(cn.name, cw.toByteArray());
		}
		JarUtils.saveAsJar(out, output);
	}

}
