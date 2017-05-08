package keycracker;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import keycracker.PublicKey;

public class ParallelCracker extends Thread {

  // Global variables
  static ParallelCracker[] threads;
  static long startTime;

  public static void main(String args[]) throws Exception {

    System.out.flush();
    System.out.println("\r");
    System.out.println("Paillier Key Cracker");

    // Get the key to crack from the arguments
    String keyName = args[0];
    System.out.println("Loading key '" + keyName + "'...");

    // Get the number of threads to use from the arguments
    String threadCount = args[1];

    // Load the key pair
    PublicKey key = loadKey(keyName);

    // Extract the key values
    BigInteger n = key.getN();
    BigInteger g = key.getG();

    System.out.println("\r");
    System.out.println("Public Key Loaded:");
    System.out.println("N = " + n.toString());
    System.out.println("G = " + g.toString());
    System.out.println("\r");
    System.out.println("Computing Private Key with " + threadCount + " Threads...");

    // Capture the calculation start time
    startTime = System.nanoTime();

    // Declare the array of threads
    threads = new ParallelCracker[Integer.parseInt(threadCount)];

    // Populate the threads
    for(int index = 0; index < threads.length; index++){
      threads[index] = new ParallelCracker(index, n);
    }

    // Start the threads
    for(int index = 0; index < threads.length; index++){
      threads[index].start();
    }

    // Wait for the threads
    for(int index = 0; index < threads.length; index++){
      threads[index].join();
    }

    // No key was found
    System.out.println("\r");
    System.out.println("No Key Found!");
  }

  // Thread values
  int threadIndex;
  BigInteger keyN;

  public ParallelCracker(int index, BigInteger n) {
    this.threadIndex = index;
    this.keyN = n;
  }

  public void run(){

    // Get the squareroot of n
    BigInteger sqrtN = sqrt(keyN);

    // If the squareroot is even increment it
    if(sqrtN.mod(BigInteger.valueOf(2)).equals(BigInteger.valueOf(0))){
      sqrtN = sqrtN.add(BigInteger.valueOf(1));
    }

    // Search through each odd number between the squareroot of n and 3 for the first prime
    for (BigInteger index1 = sqrtN.subtract(BigInteger.valueOf(threadIndex * 2));
                      index1.compareTo(BigInteger.valueOf(3)) >= 0;
                                index1 = index1.subtract(BigInteger.valueOf(threads.length * 2))) {

      // Search through each odd number between n and the squareroot of n for the second prime
      for (BigInteger index2 = sqrtN; index2.compareTo(keyN) <= 0;
                                index2 = index2.add(BigInteger.valueOf(2))) {

        // Check if the multiplication of the numbers equals n
        if (index1.multiply(index2).equals(keyN)) {

          // Check if the first number is a probable prime
          if (index1.isProbablePrime(100)) {

            // Check if the second number is a probable prime
            if (index2.isProbablePrime(100)) {

              System.out.println("\r");
              System.out.println("Potential Key Found!");
              System.out.println("Attempting Decryption...");

              // Declare the values of the potentially found key
              BigInteger potentialN = index1.multiply(index2);
              BigInteger potentialG = index1.multiply(index2).add(BigInteger.valueOf(1));
              BigInteger potentialPhiN = (index1.subtract(BigInteger.valueOf(1))).multiply(
                                          (index2.subtract(BigInteger.valueOf(1))));
              BigInteger potentialU = potentialPhiN.modInverse(potentialN);

              // Attempt to encrypt and decrypt 5 values
              BigInteger plaintext1 = new BigInteger("0");
              BigInteger plaintext2 = new BigInteger("1");
              BigInteger plaintext3 = new BigInteger("7");
              BigInteger plaintext4 = new BigInteger("77");
              BigInteger plaintext5 = new BigInteger("777");
              BigInteger cyphertext1 = encrypt(plaintext1, potentialN, potentialG);
              BigInteger cyphertext2 = encrypt(plaintext2, potentialN, potentialG);
              BigInteger cyphertext3 = encrypt(plaintext3, potentialN, potentialG);
              BigInteger cyphertext4 = encrypt(plaintext4, potentialN, potentialG);
              BigInteger cyphertext5 = encrypt(plaintext5, potentialN, potentialG);
              BigInteger decrypt1 = decrypt(cyphertext1, potentialN, potentialPhiN, potentialU);
              BigInteger decrypt2 = decrypt(cyphertext2, potentialN, potentialPhiN, potentialU);
              BigInteger decrypt3 = decrypt(cyphertext3, potentialN, potentialPhiN, potentialU);
              BigInteger decrypt4 = decrypt(cyphertext4, potentialN, potentialPhiN, potentialU);
              BigInteger decrypt5 = decrypt(cyphertext5, potentialN, potentialPhiN, potentialU);
              Boolean success = plaintext1.equals(decrypt1) && plaintext2.equals(decrypt2) &&
                  plaintext3.equals(decrypt3) && plaintext4.equals(decrypt4) && plaintext5.equals(decrypt5);

              // Check if the key has been computed
              if (success){

                // Capture the calculation end time
                long endTime = System.nanoTime();

                // Calculate the calculation time
                long calculationTime = endTime - startTime;

                // Output the values of the private key
                System.out.println("Decryption Succeeded!");
                System.out.println("\r");
                System.out.println("Private Key Computed:");
                System.out.println("PhiN = " + potentialPhiN.toString());
                System.out.println("U = " + potentialU.toString());
                System.out.println("\r");
                System.out.println("Key Computed in: " + String.valueOf(calculationTime) + " nanoseconds (Approx " + String.valueOf(calculationTime/60000000000.0) + " minutes)");
                System.out.println("\r");

                System.exit(1);
              } else {
                System.out.println("Decryption Failed!");
                System.out.println("\r");
              }
            }
          }
        }
      }
    }
  }

  // Load a key pair
  public static PublicKey loadKey(String Filename) {

    // Read the key from file
    String publicKeyFileContents = "";
    try {
      String publicKeyFilePath = "keys/public/" + Filename;
      BufferedReader publicKeyFile = new BufferedReader(new FileReader(publicKeyFilePath));
      publicKeyFileContents = publicKeyFile.readLine();
      publicKeyFile.close();
    } catch (Exception e) {}

    // Extract the public key values
    String[] publicKey = publicKeyFileContents.split(",");
    String publicKeyN = publicKey[0];
    String publicKeyG = publicKey[1];

    // Create the key pair
    return new PublicKey(publicKeyN, publicKeyG);
  }

  // Encrypt an integer
  public static BigInteger encrypt(BigInteger plaintext, BigInteger n, BigInteger g) {

    // Calculate n^2
    BigInteger nSquared = n.pow(2);

    // Generate a random 'r' where 1 < r < n - 1
    BigInteger r = randomBigInteger(n);

    // Compute the cyphertext as cyphertext = (g^plaintext mod n^2) * (r^n mod n^2) mod n^2
    BigInteger cyphertext = (g.modPow(plaintext, nSquared).multiply(r.modPow(n, nSquared))).mod(nSquared);

    // Return the encrypted cypher
    return cyphertext;
  }

  // Decrypt from cyphertext
  public static BigInteger decrypt(BigInteger cyphertext, BigInteger n, BigInteger phiN, BigInteger u) {

    // Calculate n^2
    BigInteger nSquared = n.pow(2);

    // Compute the plaintext as plaintext = L(cyphertext^phiN mod n^2) * u mod n
    // Where L(x) = (x - 1) / n
    BigInteger plaintext = cyphertext.modPow(phiN, nSquared).subtract(new BigInteger("1")).divide(n).multiply(u).mod(n);

    // Return the decrypted plaintext
    return plaintext;
  }

  // Random big integer 'r' where 1 < r < n - 1
  public static BigInteger randomBigInteger(BigInteger n) {
    Random random = new Random();
    n = n.subtract(new BigInteger("1"));
    BigInteger r;
    do {
        r = new BigInteger(n.bitLength(), random);
    } while (r.compareTo(n) >= 2);
    return r;
  }

  // Get the squareroot of a big integer
  // From: https://gist.github.com/JochemKuijpers/cd1ad9ec23d6d90959c549de5892d6cb
  public static BigInteger sqrt(BigInteger n) {
    BigInteger a = BigInteger.ONE;
    BigInteger b = n.shiftRight(5).add(BigInteger.valueOf(8));
    while (b.compareTo(a) >= 0) {
      BigInteger mid = a.add(b).shiftRight(1);
      if (mid.multiply(mid).compareTo(n) > 0) {
        b = mid.subtract(BigInteger.ONE);
      } else {
        a = mid.add(BigInteger.ONE);
      }
    }
    return a.subtract(BigInteger.ONE);
  }
}