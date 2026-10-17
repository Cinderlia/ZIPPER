About This Repository
The ZIPPER source code in this repository originates from the academic paper "ZIPPER: Static Taint Analysis for PHP Applications with Precision and Efficiency", published at USENIX Security 2025.

Paper Information:

Title: ZIPPER: Static Taint Analysis for PHP Applications with Precision and Efficiency

Authors: Xinyi Wang, Yeting Li, Jie Lu, Shizhe Cui, Chenghang Shi, Qin Mai, Yunpei Zhang, Yang Xiao, Feng Li, Wei Huo

Venue: 34th USENIX Security Symposium (USENIX Security '25), Seattle, WA, August 2025

Official Paper Link: https://www.usenix.org/conference/usenixsecurity25/presentation/wang-xinyi

Original Artifact URLs:

Zenodo record: https://zenodo.org/records/15582111 (v1, 2025-06-05)

Zenodo updated version: https://zenodo.org/records/15636541 (v2, 2025-06-11)

Note: This repository was created by an individual researcher who downloaded the artifact from the Zenodo records above and re-uploaded it to GitHub for personal academic research purposes. The code may be modified or extended in the future. If you wish to cite the ZIPPER tool or paper, please refer to the official paper and artifact information listed above.


# ZIPPER

ZIPPER is a taint-analysis tool for PHP applications, built on top of Joern's `php2cpg` component.



# Prerequisites

Before you can build and run ZIPPER, ensure the following dependencies are installed and available in your environment:
- **Java Development Kit (JDK) 17**. ZIPPER’s core is written in Scala and compiled against Java 17. Make sure the `java` binary is in your `PATH`.
- **Scala 3.4.2**. Used for writing and compiling the analysis engine.
- **Apache Maven**. Used to fetch dependencies, compile sources, and package the final JAR.
- **PHP 7.4**. Make sure the **`php`** binary (PHP 7.4) is in your `PATH`.  ZIPPER relies on `php2cpg`, which internally uses a PHP parser to build abstract syntax trees. You can download the php binary for windows from this [link](https://windows.php.net/downloads/releases/archives/php-7.4.27-nts-Win32-vc15-x64.zip).



# Build Instructions

Unzip the `ZIPPER-SourceCode.zip` and run the following Maven command from the project root (where pom.xml is located):
```
cd ZIPPER-SourceCode
mvn -B package --file pom.xml
```
Upon successful completion, the JAR with all dependencies will be created at `zipper-scan/target/zipper-scan-jar-with-dependencies.jar`.

You can also open the project in **JetBrains IntelliJ IDEA** and use the built-in Maven tool window to run the `package` goal. This provides a more convenient UI to do this.



# Usage
Once you have the zipper-scan-jar-with-dependencies.jar, you can invoke the taint-analysis as follows:

## Help Command

To see the available flags for taint:
```
java -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar help taint
```

## Default Taint Scan Command

Below is an example of the default command, which enables a comprehensive set of analysis options:
```
java -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
  --enable-sanitizer-keyword-match \
  --enable-enhanced-dynamic-call \
  --enable-global-data-dependency \
  --enable-ondemand-alias-analysis \
  --enable-reachability-analysis \
  --language PHP \
  /path/to/target-php-project
```
If your codebase uses custom recursive XSS sanitization functions, you can activate an extra recognizer: `--enable-custom-sanitizer-recognizer`.

Reachability reports can be generated with `--enable-reachability-report=path` or `--enable-reachability-report=debug`. Both options write `output/reachability-path-report.json`; `debug` also writes `output/reachability-debug-report.json`. Report generation runs reachability checks but does not filter paths unless `--enable-reachability-analysis` is also enabled.



# Docker Image

In order to test ZIPPER easily, we provide a docker image for compiling and using ZIPPER. Below are the test environments we have used to run docker:

- **OS**: Linux Mint 21.2 (based on Ubuntu 22.04)

- **Docker**: 24.0.6

## Load Docker Image

Download `zipper-public-docker.tar.gz` and run `docker load -i zipper-public-docker.tar.gz`


## Usage

After loading the image, you can start a container with the following command:

```bash
docker run --security-opt seccomp=unconfined --net host -it zipper-public:v4 /bin/bash
```

This will launch a bash shell, after which you can enter the `tool` directory by running: `cd /tool`. The directory contains the following contents:

- `ZIPPER-SourceCode`: The source code of ZIPPER.
- `graalvm-jdk-17.0.15+9.1`: The pre-downloaded JDK 17 binary. The `java` command has been replaced with a symbolic link pointing to `graalvm-jdk-17.0.15+9.1/bin/java`.
- `zipper-scan-jar-with-dependencies.jar`: The packaged JAR file of ZIPPER.
- `test-php-project`: A brief code example to test ZIPPER's functionality.

In `tool` folder, you can run this command to test whether ZIPPER works:

```
java -jar zipper-scan-jar-with-dependencies.jar taint --language PHP test-php-project/
```

It will output two files in the **output** directory:

- `taint-analysis-result.json`: The JSON format of taint analysis result.
- `taint-analysis-result.sarif`: The SARIF format for convenient code auditing. You can easily track the taint flow propagation using the **SARIF Explorer** extension in **VSCode**.

If you want to compile ZIPPER by youself, you can run the following commands:

```bash
cd ZIPPER-SourceCode
mvn -B package --file pom.xml
```



# Code Structure

The zipper-core module contains the core implementation of ZIPPER, with the following key components:

1. **Value Set Analysis**: Located in the package `bee.zipper.core.analysis.vsa`.
2. **Call Graph Construction**: Implemented in the `IterativeDynamicCallPass` class under the package `bee.zipper.core.cpgcreation.php.passes`.
3. **Taint Analysis**: Located in the package `bee.zipper.core.analysis.taint`.



# Evaluation Dataset

The 15 PHP projects used in RQ1 are located in the compressed file `PHP-Projects.zip`.



# Experimental Setup

## RQ1: Comparison to State-of-the-Art

In RQ1, ZIPPER was launched with the default arguments as demonstrated in the previous section.

## RQ2: Ablation Studies

Next are the launch commands for the four variants used in the ablation studies:

- $ZIPPER^{UTV}$​

  ```
  java -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
    --disable-enhanced-vsa \
    --enable-sanitizer-keyword-match \
    --enable-enhanced-dynamic-call \
    --enable-global-data-dependency \
    --enable-ondemand-alias-analysis \
    --enable-reachability-analysis \
    --language PHP \
    /path/to/target-php-project
  ```

- $ZIPPER^{NGDD}$​

  ```
  java -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
    --enable-sanitizer-keyword-match \
    --enable-enhanced-dynamic-call \
    --enable-ondemand-alias-analysis \
    --enable-reachability-analysis \
    --language PHP \
    /path/to/target-php-project
  ```

- $ZIPPER^{NAA}$

  ```
  java -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
    --enable-sanitizer-keyword-match \
    --enable-enhanced-dynamic-call \
    --enable-global-data-dependency \
    --enable-reachability-analysis \
    --language PHP \
    /path/to/target-php-project
  ```

- $ZIPPER^{NOD}$

  ```
  java -jar zipper-scan/target/zipper-scan-jar-with-dependencies.jar taint \
    --enable-sanitizer-keyword-match \
    --enable-enhanced-dynamic-call \
    --enable-global-data-dependency \
    --enable-object-data-dependency \
    --enable-reachability-analysis \
    --language PHP \
    /path/to/target-php-project
  ```
