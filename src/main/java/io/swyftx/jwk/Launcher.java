package io.swyftx.jwk;

// Standard Java Security & Crypto
import java.security.Security;

// Standard Java Collections
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Apache Commons CLI
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;

import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

// BouncyCastle
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Google Guava
import com.google.common.collect.ImmutableList;

// Nimbus JOSE+JWT
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;

import com.google.common.base.Strings;

/**
 * Small Helper App to generate Json Web Keys
 */
public class Launcher {

	private static Options options;

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());

		options = new Options();
		configureCommandLineOptions(options);

		try {
			CommandLineOptions parsedOptions = parseCommandLineOptions(args);
            System.out.println("Generating key...");
            JWK jwk = KeyGenerator.makeKey(
				parsedOptions.size,
				parsedOptions.generator,
				parsedOptions.keyUse,
				parsedOptions.keyAlg
			);

            System.out.println("Displaying keys in JWK format...");
			KeyWriter.displayJWK(
                jwk,
				true,
				false,
				true
			);

            System.out.println("Displaying keys in PEM format...");
            KeyWriter.displayPEM(
                jwk,
                false,
                true
            );


            // Initialize Vault client and perform update secret operation
            System.out.println("Storing private key in vault...");
            VaultClient vaultClient = new VaultClient();
            if (vaultClient.initialize()) {
                Map<String, Object> secretData = new HashMap<>();
                secretData.put("GEN2_BALANCE_SERVICE_PRIVATE_KEY", KeyWriter.privateKeyToString(jwk.toRSAKey().toPrivateKey()));
                vaultClient.writeSecret(parsedOptions.secretPath, secretData);
            }

        } catch (NumberFormatException e) {
			throw printUsageAndExit("Invalid key size: " + e.getMessage());
		} catch (ParseException e) {
			throw printUsageAndExit("Failed to parse arguments: " + e.getMessage());
		} catch (java.text.ParseException e) {
			throw printUsageAndExit("Could not parse existing KeySet: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw printUsageAndExit(e.getMessage());
        } catch (Exception e) {
            throw printUsageAndExit("Unexpected error: " + e.getMessage());
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

        if (cmd.hasOption("h")) {
            throw printUsageAndExit("Vault JWKS Generator\n");
        }

		result.size = "2048";
		result.secretPath = cmd.getOptionValue("p");
        result.generator = KeyIdGenerator.specified("sha256");
		result.keyType = KeyType.parse("RSA");
		result.keyUse =  KeyUse.parse("sig");
        result.keyAlg = JWSAlgorithm.parse("RS256");

        if (Strings.isNullOrEmpty(result.secretPath)) {
            result.secretPath = "dev/test/ross";
        }
		return result;
	}

	/**
	 * Class to hold parsed command line options
	 */
	private static class CommandLineOptions {
		String size;
        String secretPath;
		KeyIdGenerator generator;
		KeyType keyType;
		KeyUse keyUse;
		Algorithm keyAlg;
	}

    /**
     *
     * @param options Options to configure
     */
	private static void configureCommandLineOptions(Options options) {
		options.addOption("h", "help", false, "Print this help message");
        options.addOption("p", "path", true, "Vault path to write secret to");
	}

	// print out a usage message and quit
	// return exception so that we can "throw" this for control flow analysis
	private static IllegalArgumentException printUsageAndExit(String message) {
		if (message != null) {
			System.err.println(message);
		}

		List<String> optionOrder = ImmutableList.of("p", "h");

		HelpFormatter formatter = new HelpFormatter();
		formatter.setOptionComparator(Comparator.comparingInt(o -> optionOrder.indexOf(o.getOpt())));
		formatter.printHelp("java -jar json-web-key-generator.jar [options]", options);

		// kill the program
		System.exit(1);
		return new IllegalArgumentException("Program was called with invalid arguments");
	}
}
