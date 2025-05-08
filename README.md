# jwk-to-vault

A commandline Java-based generator for JSON Web Keys (JWK) and JSON Private/Shared Keys (JPSKs) that also stores generated private keys in Vault.

## Standalone run

To compile, run `mvn package`. This will generate a `json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar` in the `/target` directory.

To generate a key, run `java -jar target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar`.

```
usage: java -jar json-web-key-generator.jar [options]
 -p,--path <arg>           Vault path to write private key in PEM format to
 -h,--help                 Print help
```

## Docker

### Build with docker
Example:


```bash
# Optional TAG
#TAG="your/tag:here"
# Example: TAG="<your_docker_id>/json-web-key-generator:latest"
$ docker build -t $TAG .
```

If building from git tags then run the following to store the *tag*, and the *commit*
in the docker image label.

```bash
TAG=$(git describe --abbrev=0 --tags)
REV=$(git log -1 --format=%h)
docker build -t <your_docker_id>/json-web-key-generator:$TAG --build-arg GIT_COMMIT=$REV --build-arg GIT_TAG=$TAG .
docker push <your_docker_id>/json-web-key-generator:$TAG

# or push all the tags
docker push <your_docker_id>/json-web-key-generator --all-tags
```

### Run from docker

Example of running the app  within a docker container to generate a 2048 bit RSA JWK.

```bash
$ docker run --rm <your_docker_id>/json-web-key-generator:latest -p dev/app/jwks
Generating key...
Displaying keys in JWK format...
Public key:
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "sha256",
      "alg": "RS256",
      "n": "riMey2UNvWlgdMkRcgZ4n5nL42Hv53o40x-ORv5IimKCl8DZBNY1Vl3D7ZKxk46wxqaiefDwgxjPjCdWuLN8ppwo9GhPv-XrYQzwfXGGPELRxo-AGaS2Ox41Sju6_66tl10HnXa46mEmXsiHolINxTVZVSxJe_fCMtM9Dd4xkxWaxx1nw94zH2-4XrEZqzWiNUqq7t_dPLXb7704EYqBdp7skhlxDfjNDZSh0qHobrCrOGlm5txolfriL99rCFpSNIvLcYJDmGRxz1ougBFzXuEslHeXP4YykZfoHdr1ITcpxKV5Z-ys8yk3o8jCOSgdgF1z77y9SXcSOthkGDCJLQ"
    }
  ]
}
Storing in vault...
Attempting to initialize Vault client...
Vault client initialized successfully.
Successfully wrote secret to Vault at path: k8s/data/dev/app/jwks
Secret content: [GEN2_BALANCE_SERVICE_PRIVATE_KEY]
```
