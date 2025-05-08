package org.mitre.jose.jwk;

import org.springframework.vault.VaultException;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Client for interacting with HashiCorp Vault
 */
public class VaultClient {
    private static final String DEFAULT_VAULT_URI = "https://vault.swyftx-cicd.io";
    private static final String DEFAULT_KV_MOUNT_PATH = "k8s";

    private final String vaultUri;
    private VaultTemplate vaultTemplate;

    /**
     * Creates a VaultClient with the default Vault URI
     */
    public VaultClient() {
        this(DEFAULT_VAULT_URI);
    }

    /**
     * Creates a VaultClient with a specified Vault URI
     *
     * @param vaultUri The URI of the Vault server
     */
    public VaultClient(String vaultUri) {
        this.vaultUri = vaultUri;
    }

    /**
     * Initializes the Vault client by reading token from user's home directory
     *
     * @return true if initialization was successful, false otherwise
     */
    public boolean initialize() {
        String vaultToken = readVaultToken();

        if (vaultToken != null && !vaultToken.isEmpty()) {
            try {
                System.out.println("Attempting to initialize Vault client...");
                System.out.println("VAULT_ADDR: " + vaultUri);

                VaultEndpoint vaultEndpoint = VaultEndpoint.from(new URI(vaultUri));
                ClientAuthentication clientAuthentication = new TokenAuthentication(vaultToken);
                vaultTemplate = new VaultTemplate(vaultEndpoint, clientAuthentication);
                System.out.println("VaultTemplate initialized successfully.");
                return true;
            } catch (URISyntaxException e) {
                System.err.println("Invalid Vault URI syntax: " + vaultUri + ". Error: " + e.getMessage());
            } catch (Exception e) {
                System.err.println("Failed to initialize VaultTemplate. Error: " + e.getMessage());
            }
        } else {
            System.out.println("Vault token could not be read or is empty. Vault client will not be initialized.");
        }
        return false;
    }

    /**
     * Writes a secret to Vault
     *
     * @param secretPath The path where the secret should be stored
     * @param secretData The key-value pairs to store
     * @return true if secret was written successfully, false otherwise
     */
    public boolean writeSecret(String secretPath, Map<String, Object> secretData) {
        return writeSecret(DEFAULT_KV_MOUNT_PATH, secretPath, secretData);
    }

    /**
     * Writes a secret to Vault
     *
     * @param kvMountPath The mount path of the key-value engine
     * @param secretPath The path where the secret should be stored
     * @param secretData The key-value pairs to store
     * @return true if secret was written successfully, false otherwise
     */
    public boolean writeSecret(String kvMountPath, String secretPath, Map<String, Object> secretData) {
        if (vaultTemplate == null) {
            System.err.println("Vault client not initialized. Call initialize() first.");
            return false;
        }

        try {
            VaultVersionedKeyValueOperations kvOps = vaultTemplate.opsForVersionedKeyValue(kvMountPath);
            kvOps.put(secretPath, secretData);

            System.out.println("Successfully wrote secret to Vault at path: " + kvMountPath + "/data/" + secretPath);
            System.out.println("Secret content: " + secretData.keySet());
            return true;
        } catch (VaultException e) {
            System.err.println("Error performing Vault KV operation: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("An unexpected error occurred during Vault KV operation: " + e.getMessage());
        }
        return false;
    }

    /**
     * Reads a secret from Vault
     *
     * @param secretPath The path where the secret is stored
     * @return Map of secret data or null if retrieval failed
     */
    public Map<String, Object> readSecret(String secretPath) {
        return readSecret(DEFAULT_KV_MOUNT_PATH, secretPath);
    }

    /**
     * Reads a secret from Vault
     *
     * @param kvMountPath The mount path of the key-value engine
     * @param secretPath The path where the secret is stored
     * @return Map of secret data or null if retrieval failed
     */
    public Map<String, Object> readSecret(String kvMountPath, String secretPath) {
        if (vaultTemplate == null) {
            System.err.println("Vault client not initialized. Call initialize() first.");
            return null;
        }

        try {
            VaultVersionedKeyValueOperations kvOps = vaultTemplate.opsForVersionedKeyValue(kvMountPath);
            return kvOps.get(secretPath).getData();
        } catch (VaultException e) {
            System.err.println("Error reading secret from Vault: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("An unexpected error occurred while reading secret: " + e.getMessage());
        }
        return null;
    }

    /**
     * Reads the Vault token from the user's home directory
     *
     * @return The vault token or null if it couldn't be read
     */
    private String readVaultToken() {
        String homeDir = System.getProperty("user.home");
        File tokenFile = new File(homeDir, ".vault-token");

        if (tokenFile.exists() && tokenFile.isFile() && tokenFile.canRead()) {
            try {
                return Files.readString(Paths.get(tokenFile.getAbsolutePath())).trim();
            } catch (IOException e) {
                System.err.println("Error reading Vault token from " + tokenFile.getAbsolutePath() + ": " + e.getMessage());
            }
        } else {
            System.err.println("Vault token file not found or not readable at " + tokenFile.getAbsolutePath());
        }
        return null;
    }
}
