package keycracker;

import java.math.BigInteger;

public class PublicKey {

  // Key values
  public BigInteger n;
  public BigInteger g;

  // Constructor
  public PublicKey(String stringN, String stringG) {

    // Set the keypair values
    n = new BigInteger(stringN);
    g = new BigInteger(stringG);
  }

  // Getter functions
  BigInteger getN(){ return n; }
  BigInteger getG(){ return g; }
}