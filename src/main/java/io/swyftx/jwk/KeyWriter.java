package io.swyftx.jwk;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.AsymmetricKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;

/**
 * Utility class for writing JWK keys to files or console
 */
public class KeyWriter {

    /**
     * Displays a JWK to the console as JSON
     *
     * @param jwk JWK to print
     * @param keySet If true, print the JWK as a keyset
     * @param privateKey If true, print the private key
     * @param pubKey If true, print the public key
     */
    public static void displayJWK(JWK jwk, boolean keySet, boolean privateKey, boolean pubKey) {
        // round trip it through GSON to get a prettyprinter
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        if (privateKey) {
            System.out.println("Private key:");
            printKey(keySet, jwk, gson);
            System.out.println(); // spacer
        }

        if (pubKey) {

            // also print public key, if possible
            JWK pub = jwk.toPublicJWK();

            if (pub != null) {
                System.out.println("Public key:");
                printKey(keySet, pub, gson);
                System.out.println(); // spacer
            } else {
                System.out.println("No public key.");
                System.out.println(); // spacer
            }
        }
    }

    /**
     * Displays a JWK to the console as PEM encoded certificates
     *
     * @param jwk The JWK to print
     * @param privateKey If true, print the private key
     * @param pubKey If true, print the public key
     */
    public static void displayPEM(JWK jwk, boolean privateKey, boolean pubKey) {
        try {
            KeyType keyType = jwk.getKeyType();
            if (keyType.equals(KeyType.RSA)) {
                if (pubKey) {
                    writeKeyToConsole(jwk.toRSAKey().toPublicKey());
                }
                if (privateKey) {
                    writeKeyToConsole(jwk.toRSAKey().toPrivateKey());
                }
            } else {
                throw new IllegalArgumentException("Unknown key type for X509 encoding: " + keyType);
            }
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Error extracting keypair for X509: " + e.getMessage());
        }

    }

    /**
     * Prints a public or private JWK to the console as JSON
     *
     * @param keySet If true, print a JWK Set
     * @param jwk The JWK to print
     * @param gson The GSON instance to use
     */
    private static void printKey(boolean keySet, JWK jwk, Gson gson) {
        if (keySet) {
            JWKSet jwkSet = new JWKSet(jwk);
            JsonElement json = JsonParser.parseString(jwkSet.toJSONObject(false).toString());
            System.out.println(gson.toJson(json));
        } else {
            JsonElement json = JsonParser.parseString(jwk.toJSONString());
            System.out.println(gson.toJson(json));
        }
    }

    /**
     * Generate and display a self-signed certificate to the console in PEM encoded format from a JWK
     *
     * @param jwk The JWK to use
     */
    public static void displaySelfSignedCertificate(JWK jwk) {
        try {
            KeyType keyType = jwk.getKeyType();
            if (keyType.equals(KeyType.RSA)) {
                Certificate cert = selfSign(jwk.toRSAKey().toPublicKey(),
                        jwk.toRSAKey().toPrivateKey(),
                        jwk.getKeyID() != null ? jwk.getKeyID() : jwk.computeThumbprint().toString(),
                        "SHA256withRSA"
                );
                writeCertificateToConsole(cert);
            } else {
                throw new IllegalArgumentException("Unknown key type for X509 encoding: " + keyType);
            }
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Error extracting keypair for X509: " + e.getMessage());
        }
    }


    /**
     * Writes a key to a file
     */
    private static void writeKeyToFile(boolean keySet, String outFile, String pubOutFile, JWK jwk, Gson gson) throws IOException,
            java.text.ParseException {
        JsonElement json;
        JsonElement pubJson;
        File output = new File(outFile);
        if (keySet) {
            List<JWK> existingKeys = output.exists() ? JWKSet.load(output).getKeys() : Collections.emptyList();
            List<JWK> jwkList = new ArrayList<>(existingKeys);
            jwkList.add(jwk);
            JWKSet jwkSet = new JWKSet(jwkList);
            json = JsonParser.parseString(jwkSet.toJSONObject(false).toString());
            pubJson = JsonParser.parseString(jwkSet.toJSONObject(true).toString());
        } else {
            json = JsonParser.parseString(jwk.toJSONString());
            pubJson = JsonParser.parseString(jwk.toPublicJWK().toJSONString());
        }
        try (Writer os = new BufferedWriter(new FileWriter(output))) {
            os.write(gson.toJson(json));
        }
        if (pubOutFile != null) {
            try (Writer os = new BufferedWriter(new FileWriter(pubOutFile))) {
                os.write(gson.toJson(pubJson));
            }
        }
    }

    /**
     * Writes keys to the console in PEM encoded format
     *
     * @param key The public or private key to display
     */
    private static void writeKeyToConsole(AsymmetricKey key) {
        try {
            System.out.println(); // spacer

            PemWriter pw = new PemWriter(new OutputStreamWriter(System.out));

            switch (key) {
                case PrivateKey privateKey -> {
                    System.out.println("X509 Formatted Private Key:");
                    pw.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
                }
                case PublicKey publicKey -> {
                    System.out.println("X509 Formatted Public Key:");
                    pw.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
                }
                default -> {
                    System.out.println("Unknown key type for X509 encoding: " + key);
                }
            }

            pw.flush();
        } catch (IOException e) {
            throw new IllegalArgumentException("Error printing X509 format: " + e.getMessage());
        }
    }

    /**
     * Writes PEM formatted certificates to the console
     *
     * @param cert The certificate to write
     */
    private static void writeCertificateToConsole(Certificate cert) {
        try {
            System.out.println();
            System.out.println("X509 Formatted Certificate:");

            PemWriter pw = new PemWriter(new OutputStreamWriter(System.out));

            if (cert != null) {
                pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
            }

            pw.flush();
        } catch (IOException | CertificateEncodingException e) {
            throw new IllegalArgumentException("Error printing X509 format: " + e.getMessage());
        }
    }

    /**
     * Writes a PEM formatted private key to a string buffer and returns the result
     *
     * @param privateKey the private key to write, may be null
     * @return String containing the PEM formatted private key
     */
    public static String privateKeyToString(PrivateKey privateKey) {
        try {
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);

            if (privateKey != null) {
                pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            }

            pemWriter.flush();
            pemWriter.close();

            return stringWriter.toString();
        } catch (IOException e) {
            throw new IllegalArgumentException("Error creating PEM format: " + e.getMessage());
        }
    }

    /**
     * Creates a self-signed certificate
     *
     * @param pub Public key to match private key
     * @param priv Private key to sign with
     * @param subjectDN Subject DN to use
     * @param signatureAlgorithm Signature algorithm to use
     * @return Certificate
     */
    public static Certificate selfSign(PublicKey pub, PrivateKey priv, String subjectDN, String signatureAlgorithm) {
        try {
            X500Name dn = new X500Name("CN=" + URLEncoder.encode(subjectDN, Charset.defaultCharset()));

            BigInteger certSerialNumber = BigInteger.valueOf(Instant.now().toEpochMilli());

            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                .build(priv);

            Instant startDate = Instant.now();
            Instant endDate = startDate.plus(300, ChronoUnit.DAYS);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dn, certSerialNumber, Date.from(startDate), Date.from(endDate),
                dn, pub);

            return new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(contentSigner));
        } catch (CertificateException | OperatorCreationException e) {
            throw new IllegalArgumentException("Unable to create certificate: " + e.getMessage());
        }
    }
}
