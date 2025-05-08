package org.mitre.jose.jwk;

// Standard Java I/O and NIO
import java.io.IOException;

// Standard Java Security & Crypto
import java.security.Security;

// Standard Java Collections
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// Apache Commons CLI
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

// BouncyCastle
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Google Guava
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

// Nimbus JOSE+JWT
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
/**
 * Small Helper App to generate Json Web Keys
 */
public class Launcher {

	private static Options options;

	private static final List<KeyType> keyTypes = List.of(KeyType.RSA);

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());

		// Initialize Vault client and perform test operation
		VaultClient vaultClient = new VaultClient();
		if (vaultClient.initialize()) {
			Map<String, Object> secretData = new HashMap<>();
			secretData.put("TEST_KEY", "TEST_VALUE");
			vaultClient.writeSecret("dev/test/ross", secretData);
		}

		options = new Options();
		configureCommandLineOptions(options);

		try {
			CommandLineOptions parsedOptions = parseCommandLineOptions(args);

			JWK jwk = makeKey(
				parsedOptions.size,
				parsedOptions.generator,
				parsedOptions.keyType,
				parsedOptions.keyUse,
				parsedOptions.keyAlg
			);

			KeyWriter.outputKey(
				parsedOptions.keySet,
				parsedOptions.pubKey,
				parsedOptions.outFile,
				parsedOptions.pubOutFile,
				parsedOptions.printX509,
				jwk
			);
		} catch (NumberFormatException e) {
			throw printUsageAndExit("Invalid key size: " + e.getMessage());
		} catch (ParseException e) {
			throw printUsageAndExit("Failed to parse arguments: " + e.getMessage());
		} catch (java.text.ParseException e) {
			throw printUsageAndExit("Could not parse existing KeySet: " + e.getMessage());
		} catch (IOException e) {
			throw printUsageAndExit("Could not read existing KeySet: " + e.getMessage());
		}
	}

	/**
	 * Parse command line arguments
	 *
	 * @param args Command line arguments
	 * @return Parsed command line options
	 * @throws ParseException If parsing fails
	 * @throws java.text.ParseException If key usage parsing fails
	 */
	private static CommandLineOptions parseCommandLineOptions(String[] args) throws ParseException, java.text.ParseException {
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd = parser.parse(options, args);

		CommandLineOptions result = new CommandLineOptions();

		result.kty = cmd.getOptionValue("t");
		result.size = cmd.getOptionValue("s");
		result.use = cmd.getOptionValue("u");
		result.alg = cmd.getOptionValue("a");
		result.keySet = cmd.hasOption("S");
		result.pubKey = cmd.hasOption("p");
		result.outFile = cmd.getOptionValue("o");
		result.pubOutFile = cmd.getOptionValue("P");
		result.printX509 = cmd.hasOption("x");

		// process the Key ID
		String kid = cmd.getOptionValue("i");
		if (Strings.isNullOrEmpty(kid)) {
			// no explicit key ID is specified, see if we should use a generator
			if (cmd.hasOption("i") || cmd.hasOption("I")) {
				// Either -I is set, -i is set (but an empty value is passed), either way it's a blank key ID
				result.generator = KeyIdGenerator.NONE;
			} else {
				result.generator = KeyIdGenerator.get(cmd.getOptionValue("g"));
			}
		} else {
			result.generator = KeyIdGenerator.specified(kid);
		}

		// check for required fields
		if (result.kty == null) {
			throw printUsageAndExit("Key type must be supplied.");
		}

		// parse out the important bits
		result.keyType = KeyType.parse(result.kty);
		result.keyUse = validateKeyUse(result.use);

		if (!Strings.isNullOrEmpty(result.alg)) {
			result.keyAlg = JWSAlgorithm.parse(result.alg);
		}

		return result;
	}

	/**
	 * Class to hold parsed command line options
	 */
	private static class CommandLineOptions {
		String kty;
		String size;
		String use;
		String alg;
		boolean keySet;
		boolean pubKey;
		String outFile;
		String pubOutFile;
		boolean printX509;
		KeyIdGenerator generator;
		KeyType keyType;
		KeyUse keyUse;
		Algorithm keyAlg;
	}

	private static void configureCommandLineOptions(Options options) {
		options.addOption("t", "type", true, "Key Type, one of: " +
			keyTypes.stream()
		.map(KeyType::getValue)
		.collect(Collectors.joining(", ")));

		options.addOption("s", "size", true,
			"Key Size in bits, required for " + KeyType.RSA.getValue() + " key types. Must be an integer divisible by 8");
		options.addOption("u", "usage", true, "Usage, one of: enc, sig (optional)");
		options.addOption("a", "algorithm", true, "Algorithm (optional)");

		OptionGroup idGroup = new OptionGroup();
		idGroup.addOption(new Option("i", "id", true, "Key ID (optional), one will be generated if not defined"));
		idGroup.addOption(new Option("I", "noGenerateId", false, "<deprecated> Don't generate a Key ID. (Deprecated, use '-g none' instead.)"));
		idGroup.addOption(new Option("g", "idGenerator", true, "Key ID generation method (optional). Can be one of: "
			+ KeyIdGenerator.values().stream()
			.map(KeyIdGenerator::getName)
			.collect(Collectors.joining(", "))
			+ ". If omitted, generator method defaults to '" + KeyIdGenerator.TIMESTAMP.getName() + "'."));
		options.addOptionGroup(idGroup);

		options.addOption("p", "showPubKey", false, "Display public key separately (if applicable)");
		options.addOption("S", "keySet", false, "Wrap the generated key in a KeySet");

		options.addOption("x", "x509", false, "Display keys in X509 PEM format");

		options.addOption("o", "output", true, "Write output to file. Will append to existing KeySet if -S is used. "
			+ "Key material will not be displayed to console.");
		options.addOption("P", "pubKeyOutput", true, "Write public key to separate file. Will append to existing KeySet if -S is used. "
			+ "Key material will not be displayed to console. '-o/--output' must be declared as well.");
	}

	private static KeyUse validateKeyUse(String use) {
		try {
			return KeyUse.parse(use);
		} catch (java.text.ParseException e) {
			throw printUsageAndExit("Invalid key usage, must be 'sig' or 'enc', got " + use);
		}
	}

	private static JWK makeKey(String size, KeyIdGenerator kid, KeyType keyType, KeyUse keyUse, Algorithm keyAlg) {
		try {
			return KeyGenerator.makeKey(size, kid, keyType, keyUse, keyAlg);
		} catch (IllegalArgumentException e) {
			throw printUsageAndExit(e.getMessage());
		}
	}

	// print out a usage message and quit
	// return exception so that we can "throw" this for control flow analysis
	private static IllegalArgumentException printUsageAndExit(String message) {
		if (message != null) {
			System.err.println(message);
		}

		List<String> optionOrder = ImmutableList.of("t", "s", "u", "a", "i", "I", "g", "p", "S", "x", "o", "P");

		HelpFormatter formatter = new HelpFormatter();
		formatter.setOptionComparator(Comparator.comparingInt(o -> optionOrder.indexOf(o.getOpt())));
		formatter.printHelp("java -jar json-web-key-generator.jar -t <keyType> [options]", options);

		// kill the program
		System.exit(1);
		return new IllegalArgumentException("Program was called with invalid arguments");
	}
}
