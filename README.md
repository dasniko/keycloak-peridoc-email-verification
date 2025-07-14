# ZLB Keycloak Extensions

## General

These custom extensions are based on
![](https://img.shields.io/badge/Keycloak-26.3-blue)
![](https://img.shields.io/badge/Java-21-f89820)

### Building the Binaries

You can build the binaries, if you have a local installation of JDK, with

    $ ./mvnw clean package

If you don't have local JDK installation, but Docker is available, you can use the helper script

    $ ./build-with-docker.sh

Both approaches will build the binary `target/keycloak-extensions.jar`.

### Deployment

Deploy the built JAR file into the `$KEYCLOAK_HOME/providers` folder of your Keycloak server (or copy it to your Docker image).

When running Keycloak in `optimized` mode, you'll have to run a `build` after deploying the JAR.
If you start Keycloak regularly, an implicit build will be performed.
See [Keycloak Docs](https://www.keycloak.org/docs) and [Keycloak Guides](https://www.keycloak.org/guides) for more info.
