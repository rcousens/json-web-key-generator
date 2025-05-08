package org.mitre.jose.jwk;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.Charset;
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
     * Outputs the key to either the console or a file, based on the parameters
     */
    public static void outputKey(boolean keySet, boolean pubKey, String outFile, String pubOutFile, boolean printX509, JWK jwk)
            throws IOException, java.text.ParseException {
        // round trip it through GSON to get a prettyprinter
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        if (outFile == null) {

            System.out.println("Full key:");

            printKey(keySet, jwk, gson);

            if (pubKey) {
                System.out.println(); // spacer

                // also print public key, if possible
                JWK pub = jwk.toPublicJWK();

                if (pub != null) {
                    System.out.println("Public key:");
                    printKey(keySet, pub, gson);
                } else {
                    System.out.println("No public key.");
                }
            }

            if (printX509) {

                try {
                    KeyType keyType = jwk.getKeyType();
                    if (keyType.equals(KeyType.RSA)) {
                        Certificate cert = selfSign(jwk.toRSAKey().toPublicKey(),
                            jwk.toRSAKey().toPrivateKey(),
                            jwk.getKeyID() != null ? jwk.getKeyID() : jwk.computeThumbprint().toString(),
                            "SHA256withRSA"
                            );
                        writePEMToConsole(
                            jwk.toRSAKey().toPublicKey(),
                            jwk.toRSAKey().toPrivateKey(),
                            cert
                            );
                    } else {
                        throw new IllegalArgumentException("Unknown key type for X509 encoding: " + keyType);
                    }
                } catch (JOSEException e) {
                    throw new IllegalArgumentException("Error extracting keypair for X509: " + e.getMessage());
                }
            }

        } else {
            writeKeyToFile(keySet, outFile, pubOutFile, jwk, gson);
        }
    }

    /**
     * Prints a key to the console
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
     * Writes PEM formatted keys to the console
     */
    private static void writePEMToConsole(PublicKey publicKey, PrivateKey privateKey, Certificate cert) {
        try {
            System.out.println();
            System.out.println("X509 Formatted Keys:");

            PemWriter pw = new PemWriter(new OutputStreamWriter(System.out));

            if (publicKey != null) {
                pw.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            }

            if (privateKey != null) {
                pw.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            }

            if (cert != null) {
                pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
            }

            pw.flush();
            pw.close();
        } catch (IOException | CertificateEncodingException e) {
            throw new IllegalArgumentException("Error printing X509 format: " + e.getMessage());
        }
    }

    /**
     * Creates a self-signed certificate
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
