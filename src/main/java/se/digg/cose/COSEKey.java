// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec;
import java.security.spec.RSAOtherPrimeInfo;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;

/**
 *
 * @author jimsch
 */
public class COSEKey {

  protected CBORObject keyMap;
  private PrivateKey privateKey;
  private PublicKey publicKey;
  private CryptoContext cryptoContext = new CryptoContext(null);

  public COSEKey() {
    keyMap = CBORObject.NewMap();
  }

  /**
   * Gets the {@link CryptoContext} to set a different JCA Provider
   */
  public CryptoContext getCryptoContext() {
    return cryptoContext;
  }

  public COSEKey(CBORObject keyData) throws CoseException {
    if (keyData.getType() != CBORType.Map) {
      throw new CoseException(
          "Key data is malformed");
    }
    keyMap = keyData;
    CheckKeyState();
  }

  /**
   * Create a COSEKey object from Java Public/Private keys.
   *
   * @param pubKey - public key to use - may be null
   * @param privKey - private key to use - may be null
   * @throws CoseException Internal COSE Exception
   */
  public COSEKey(PublicKey pubKey, PrivateKey privKey) throws CoseException {
    keyMap = CBORObject.NewMap();

    if (pubKey != null) {
      ArrayList<ASN1.TagValue> spki = ASN1.DecodeSubjectPublicKeyInfo(
          pubKey.getEncoded());
      ArrayList<ASN1.TagValue> alg = spki.get(0).list;
      if (Arrays.equals(alg.get(0).value, ASN1.oid_ecPublicKey)) {
        byte[] oid = (byte[]) alg.get(1).value;
        if (oid == null) {
          throw new CoseException("Invalid SPKI structure");
        }
        // EC2 Key
        keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        if (Arrays.equals(oid, ASN1.Oid_secp256r1)) {
          keyMap.Add(
              KeyKeys.EC2_Curve.AsCBOR(),
              KeyKeys.EC2_P256);
        } else if (Arrays.equals(oid, ASN1.Oid_secp384r1)) {
          keyMap.Add(
              KeyKeys.EC2_Curve.AsCBOR(),
              KeyKeys.EC2_P384);
        } else if (Arrays.equals(oid, ASN1.Oid_secp521r1)) {
          keyMap.Add(
              KeyKeys.EC2_Curve.AsCBOR(),
              KeyKeys.EC2_P521);
        } else {
          throw new CoseException("Unsupported curve");
        }

        byte[] keyData = (byte[]) spki.get(1).value;
        if (keyData[1] == 2 || keyData[1] == 3) {
          keyMap.Add(
              KeyKeys.EC2_X.AsCBOR(),
              Arrays.copyOfRange(keyData, 2, keyData.length));
          keyMap.Add(KeyKeys.EC2_Y.AsCBOR(), keyData[1] != 2);
        } else if (keyData[1] == 4) {
          int keyLength = (keyData.length - 2) / 2;
          keyMap.Add(
              KeyKeys.EC2_X.AsCBOR(),
              Arrays.copyOfRange(keyData, 2, 2 + keyLength));
          keyMap.Add(
              KeyKeys.EC2_Y.AsCBOR(),
              Arrays.copyOfRange(keyData, 2 + keyLength, keyData.length));
        } else {
          throw new CoseException("Invalid key data");
        }
      } else if (Arrays.equals(alg.get(0).value, ASN1.Oid_rsaEncryption)) {
        ASN1.TagValue compound = ASN1.DecodeCompound(1, spki.get(1).value);
        if (compound.list == null || compound.list.size() != 2) {
          throw new CoseException("Invalid SPKI structure");
        }

        ASN1.TagValue n = compound.list.get(0);
        ASN1.TagValue e = compound.list.get(1);

        if (n.tag != 2 || e.tag != 2) {
          throw new CoseException("Invalid SPKI structure");
        }

        keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_RSA);
        keyMap.Add(KeyKeys.RSA_N.AsCBOR(), n.value);
        keyMap.Add(KeyKeys.RSA_E.AsCBOR(), e.value);
      } else if (ASN1.isEdXOid(alg.get(0).value)) {
        byte[] oid = (byte[]) alg.get(0).value;
        if (oid == null) {
          throw new CoseException("Invalid SPKI structure");
        }

        // OKP Key
        keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
        keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.EDDSA.AsCBOR());
        if (Arrays.equals(oid, ASN1.Oid_X25519)) {
          keyMap.Add(
              KeyKeys.OKP_Curve.AsCBOR(),
              KeyKeys.OKP_X25519);
        } else if (Arrays.equals(oid, ASN1.Oid_X448)) {
          keyMap.Add(
              KeyKeys.OKP_Curve.AsCBOR(),
              KeyKeys.OKP_X448);
        } else if (Arrays.equals(oid, ASN1.Oid_Ed25519)) {
          keyMap.Add(
              KeyKeys.OKP_Curve.AsCBOR(),
              KeyKeys.OKP_Ed25519);
        } else if (Arrays.equals(oid, ASN1.Oid_Ed448)) {
          keyMap.Add(
              KeyKeys.OKP_Curve.AsCBOR(),
              KeyKeys.OKP_Ed448);
        } else {
          throw new CoseException("Unsupported curve");
        }

        byte[] keyData = (byte[]) spki.get(1).value;
        if (keyData[0] == 0) {
          keyMap.Add(
              KeyKeys.OKP_X.AsCBOR(),
              Arrays.copyOfRange(keyData, 1, keyData.length));
        } else {
          throw new CoseException("Invalid key data");
        }
      } else {
        throw new CoseException("Unsupported Algorithm");
      }

      this.publicKey = pubKey;
    }

    if (privKey != null) {
      ArrayList<ASN1.TagValue> pkl = ASN1.DecodePKCS8Structure(
          privKey.getEncoded());
      if (pkl.get(0).tag != 2) {
        throw new CoseException(
            "Invalid PKCS8 structure");
      }
      ArrayList<ASN1.TagValue> alg = pkl.get(1).list;

      if (Arrays.equals(alg.get(0).value, ASN1.oid_ecPublicKey)) {
        byte[] oid = (byte[]) alg.get(1).value;
        if (oid == null) {
          throw new CoseException("Invalid PKCS8 structure");
        }
        // EC2 Key
        if (!keyMap.ContainsKey(KeyKeys.KeyType.AsCBOR())) {
          keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
          if (Arrays.equals(oid, ASN1.Oid_secp256r1)) {
            keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
          } else if (Arrays.equals(oid, ASN1.Oid_secp384r1)) {
            keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P384);
          } else if (Arrays.equals(oid, ASN1.Oid_secp521r1)) {
            keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P521);
          } else {
            throw new CoseException("Unsupported curve");
          }
        } else {
          if (!this.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_EC2)) {
            throw new CoseException("Public/Private key don't match");
          }
        }

        ArrayList<ASN1.TagValue> pkdl = ASN1.DecodePKCS8EC(pkl);
        if (pkdl.get(1).tag != 4) {
          throw new CoseException(
              "Invalid PKCS8 structure");
        }
        byte[] keyData = pkdl.get(1).value;
        keyMap.Add(KeyKeys.EC2_D.AsCBOR(), keyData);
      } else if (Arrays.equals(alg.get(0).value, ASN1.Oid_rsaEncryption)) {
        ArrayList<ASN1.TagValue> pkdl = ASN1.DecodePKCS8RSA(pkl);

        if (!keyMap.ContainsKey(KeyKeys.RSA_N.AsCBOR())) {
          keyMap.Add(KeyKeys.RSA_N.AsCBOR(), pkdl.get(1).value);
        }

        if (!keyMap.ContainsKey(KeyKeys.RSA_E.AsCBOR())) {
          keyMap.Add(KeyKeys.RSA_E.AsCBOR(), pkdl.get(2).value);
        }

        keyMap.Add(KeyKeys.RSA_D.AsCBOR(), pkdl.get(3).value);
        keyMap.Add(KeyKeys.RSA_P.AsCBOR(), pkdl.get(4).value);
        keyMap.Add(KeyKeys.RSA_Q.AsCBOR(), pkdl.get(5).value);
        keyMap.Add(KeyKeys.RSA_DP.AsCBOR(), pkdl.get(6).value);
        keyMap.Add(KeyKeys.RSA_DQ.AsCBOR(), pkdl.get(7).value);
        keyMap.Add(KeyKeys.RSA_QI.AsCBOR(), pkdl.get(8).value);
        // todo multi prime keys
      } else if (ASN1.isEdXOid(alg.get(0).value)) {
        byte[] oid = (byte[]) alg.get(0).value;
        if (oid == null)
          throw new CoseException("Invalid PKCS8 structure");
        // OKP Key
        if (!keyMap.ContainsKey(KeyKeys.KeyType.AsCBOR())) {
          keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.EDDSA.AsCBOR());
          if (Arrays.equals(oid, ASN1.Oid_X25519)) {
            keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_X25519);
          } else if (Arrays.equals(oid, ASN1.Oid_X448)) {
            keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_X448);
          } else if (Arrays.equals(oid, ASN1.Oid_Ed25519)) {
            keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
          } else if (Arrays.equals(oid, ASN1.Oid_Ed448)) {
            keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed448);
          } else {
            throw new CoseException("Unsupported curve");
          }
        } else {
          if (!this.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_OKP)) {
            throw new CoseException("Public/Private key don't match");
          }
        }

        ArrayList<ASN1.TagValue> pkdl = ASN1.DecodePKCS8EC(pkl);
        if (pkdl.get(0).tag != 4)
          throw new CoseException(
              "Invalid PKCS8 structure");
        byte[] keyData = (byte[]) pkdl.get(0).value;
        keyMap.Add(KeyKeys.OKP_D.AsCBOR(), keyData);
      } else {
        throw new CoseException("Unsupported Algorithm");
      }

      this.privateKey = privKey;
    }
  }

  public void add(KeyKeys keyValue, CBORObject value) {
    keyMap.Add(keyValue.AsCBOR(), value);
  }

  public void add(CBORObject keyValue, CBORObject value) {
    keyMap.Add(keyValue, value);
  }

  public CBORObject get(KeyKeys keyValue) {
    return keyMap.get(keyValue.AsCBOR());
  }

  public CBORObject get(CBORObject keyValue) throws CoseException {
    if ((keyValue.getType() != CBORType.Integer)
        && (keyValue.getType() != CBORType.TextString)) {
      throw new CoseException("keyValue type is incorrect");
    }
    return keyMap.get(keyValue);
  }

  /**
   * Compares the key's assigned algorithm with the provided value, indicating if the values are the
   * same.
   *
   * @param algorithmId the algorithm to compare or {@code null} to check for no assignment.
   * @return {@code true} if the current key has the provided algorithm assigned, or {@code false}
   *         otherwise
   */
  public boolean HasAlgorithmID(AlgorithmID algorithmId) {
    CBORObject thisObj = get(KeyKeys.Algorithm);
    CBORObject thatObj = algorithmId == null ? null : algorithmId.AsCBOR();
    boolean result;

    if (thatObj == null) {
      result = (thisObj == null);
    } else {
      result = thatObj.equals(thisObj);
    }
    return result;
  }

  /**
   * Compares the key's assigned identifier with the provided value, indicating if the values are
   * the same.
   *
   * @param id the identifier to compare or {@code null} to check for no assignment.
   * @return {@code true} if the current key has the provided identifier assigned, or {@code false}
   *         otherwise
   */
  @Deprecated
  public boolean HasKeyID(String id) {
    byte[] idB = StandardCharsets.UTF_8.encode(id).array();
    return HasKeyID(idB);
  }

  public boolean HasKeyID(byte[] id) {
    CBORObject thatObj = (id == null) ? null : CBORObject.FromByteArray(id);
    CBORObject thisObj = get(KeyKeys.KeyId);
    boolean result;
    if (thatObj == null) {
      result = (thisObj == null);
    } else {
      result = thatObj.equals(thisObj);
    }
    return result;
  }

  /**
   * Compares the key's assigned key type with the provided value, indicating if the values are the
   * same.
   *
   * @param keyTypeObj the key type to compare or {@code null} to check for no assignment.
   * @return {@code true} if the current key has the provided identifier assigned, or {@code false}
   *         otherwise
   */
  public boolean HasKeyType(CBORObject keyTypeObj) {
    CBORObject thatObj = keyTypeObj;
    CBORObject thisObj = get(KeyKeys.KeyType);
    boolean result;
    if (thatObj == null) {
      result = (thisObj == null);
    } else {
      result = thatObj.equals(thisObj);
    }
    return result;
  }

  /**
   * Compares the key's assigned key operations with the provided value, indicating if the provided
   * value was found in the key operation values assigned to the key.
   *
   * @param that the integer operation value to attempt to find in the values provided by the key or
   *        {@code null} to check for no assignment.
   * @return {@code true} if the current key has the provided value assigned, or {@code false}
   *         otherwise
   */
  public boolean HasKeyOp(Integer that) {
    CBORObject thisObj = get(KeyKeys.Key_Ops);
    boolean result;
    if (that == null) {
      result = (thisObj == null);
    } else {
      result = false;
      if (thisObj.getType() == CBORType.Integer) {
        if (thisObj.AsInt32() == that) {
          result = true;
        }
      } else if (thisObj.getType() == CBORType.Array) {
        for (int i = 0; i < thisObj.size(); i++) {
          if ((thisObj.get(i).getType() == CBORType.Integer)
              && (thisObj.get(i).AsInt32() == that)) {
            result = true;
            break;
          }
        }
      }
    }
    return result;
  }

  private void CheckKeyState() throws CoseException {
    CBORObject val;

    // Must have a key type
    val = get(KeyKeys.KeyType);
    if ((val == null) || (val.getType() != CBORType.Integer))
      throw new CoseException("Missing or incorrect key type field");

    if (val.equals(KeyKeys.KeyType_Octet)) {
      val = get(KeyKeys.Octet_K);
      if ((val == null) || (val.getType() != CBORType.ByteString))
        throw new CoseException("Malformed key structure");
    } else if (val.equals(KeyKeys.KeyType_EC2)) {
      CheckECKey();
    } else if (val.equals(KeyKeys.KeyType_OKP)) {
      CheckOkpKey();
    } else if (val.equals(KeyKeys.KeyType_RSA)) {
      CheckRsaKey();
    } else
      throw new CoseException("Unsupported key type");
  }

  private void CheckECKey() throws CoseException {
    // ECParameterSpec params = null; // new ECDomainParameters(curve.getCurve(),
    // curve.getG(), curve.getN(), curve.getH());
    boolean needPublic = false;
    // ECPrivateKeySpec privKeySpec = null;
    CBORObject val;

    byte[] oid;
    CBORObject cn = this.get(KeyKeys.EC2_Curve);
    if (cn == KeyKeys.EC2_P256) {
      oid = ASN1.Oid_secp256r1;
    } else if (cn == KeyKeys.EC2_P384) {
      oid = ASN1.Oid_secp384r1;
    } else if (cn == KeyKeys.EC2_P521) {
      oid = ASN1.Oid_secp521r1;
    } else {
      throw new CoseException("Key has an unknown curve");
    }

    try {
      val = this.get(KeyKeys.EC2_D);
      if (val != null) {
        if (val.getType() != CBORType.ByteString) {
          throw new CoseException(
              "Malformed key structure");
        }
        try {
          byte[] privateBytes = ASN1.EncodeEcPrivateKey(
              oid,
              val.GetByteString(),
              null);
          byte[] pkcs8 = ASN1.EncodePKCS8(
              ASN1.AlgorithmIdentifier(ASN1.oid_ecPublicKey, oid),
              privateBytes,
              null);

          KeyFactory fact = cryptoContext.getProvider() != null
              ? KeyFactory.getInstance("EC", cryptoContext.getProvider())
              : KeyFactory.getInstance("EC");
          KeySpec keyspec = new PKCS8EncodedKeySpec(pkcs8);

          privateKey = fact.generatePrivate(keyspec);
        } catch (NoSuchAlgorithmException e) {
          throw new CoseException("Unsupported Algorithm", e);
        } catch (InvalidKeySpecException e) {
          throw new CoseException("Invalid Private Key", e);
        }
      }

      val = this.get(KeyKeys.EC2_X);
      if (val == null) {
        if (privateKey == null) {
          throw new CoseException(
              "Malformed key structure");
        } else
          needPublic = true;
      } else if (val.getType() != CBORType.ByteString)
        throw new CoseException(
            "Malformed key structure");

      val = this.get(KeyKeys.EC2_Y);
      if (val == null) {
        if (privateKey == null)
          throw new CoseException(
              "Malformed key structure");
        else
          needPublic = true;
      } else if ((val.getType() != CBORType.ByteString) &&
          (val.getType() != CBORType.Boolean))
        throw new CoseException("Malformed key structure");

      if (privateKey != null && needPublic) {
        privateKey.getEncoded();

        return;
        // todo: calculate (and populate) public from private
      }

      byte[] spki = null;

      if (spki == null) {
        byte[] rgbKey = null;
        byte[] X = this.get(KeyKeys.EC2_X).GetByteString();

        if (this.get(KeyKeys.EC2_Y).getType() == CBORType.Boolean) {
          rgbKey = new byte[X.length + 1];
          System.arraycopy(X, 0, rgbKey, 1, X.length);
          rgbKey[0] = (byte) (2 +
              (this.get(KeyKeys.EC2_Y).AsBoolean() ? 1 : 0));
        } else {
          byte[] Y = this.get(KeyKeys.EC2_Y).GetByteString();
          rgbKey = new byte[X.length + Y.length + 1];
          System.arraycopy(X, 0, rgbKey, 1, X.length);
          System.arraycopy(Y, 0, rgbKey, 1 + X.length, Y.length);
          rgbKey[0] = 4;
        }

        spki = ASN1.EncodeSubjectPublicKeyInfo(
            ASN1.AlgorithmIdentifier(ASN1.oid_ecPublicKey, oid),
            rgbKey);
      }

      KeyFactory fact = cryptoContext.getProvider() != null
          ? KeyFactory.getInstance("EC", cryptoContext.getProvider())
          : KeyFactory.getInstance("EC");
      KeySpec keyspec = new X509EncodedKeySpec(spki);
      publicKey = fact.generatePublic(keyspec);
    } catch (NoSuchAlgorithmException e) {
      throw new CoseException("Alorithm unsupported", e);
    } catch (InvalidKeySpecException e) {
      throw new CoseException("Internal error on SPKI", e);
    }
    /*
     * catch (NoSuchProviderException e) { throw new CoseException("BC not found"); }
     */
    /*
     * X9ECParameters curve = GetCurve(); ECDomainParameters params = new
     * ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH()); boolean
     * needPublic = false; ECPrivateKeyParameters privKey = null; ECPublicKeyParameters pubKey =
     * null; CBORObject val;
     *
     * val = COSEKey.this.get(KeyKeys.EC2_D); if (val != null) { if (val.getType() !=
     * CBORType.ByteString) throw new CoseException("Malformed key structure"); privKey = new
     * ECPrivateKeyParameters(new BigInteger(1, val.GetByteString()), params); }
     *
     * val = COSEKey.this.get(KeyKeys.EC2_X); if (val == null) { if (privKey == null) throw new
     * CoseException("Malformed key structure"); else needPublic = true; } else if (val.getType() !=
     * CBORType.ByteString) throw new CoseException("Malformed key structure");
     *
     * val = COSEKey.this.get(KeyKeys.EC2_Y); if (val == null) { if (privKey == null) throw new
     * CoseException("Malformed key structure"); else needPublic = true; } else if ((val.getType()
     * != CBORType.ByteString) && (val.getType() != CBORType.Boolean)) throw new
     * CoseException("Malformed key structure");
     *
     * if (privKey != null && needPublic) { // todo: calculate (and populate) public from private
     * pubKey = new ECPublicKeyParameters(params.getG().multiply(privKey.getD()), params); byte[]
     * rgbX = pubKey.getQ().normalize().getXCoord().getEncoded(); byte[] rgbY =
     * pubKey.getQ().normalize().getYCoord().getEncoded(); add(KeyKeys.EC2_X,
     * CBORObject.FromByteArray(rgbX)); add(KeyKeys.EC2_Y, CBORObject.FromByteArray(rgbY)); } else {
     * // todo: validate public on curve }
     */
  }

  public ECGenParameterSpec GetCurve2() throws CoseException {
    if (get(KeyKeys.KeyType) != KeyKeys.KeyType_EC2)
      throw new CoseException(
          "Not an EC2 key");
    CBORObject cnCurve = get(KeyKeys.EC2_Curve);

    if (cnCurve == KeyKeys.EC2_P256) {
      return new ECGenParameterSpec("secp256r1");
    }
    if (cnCurve == KeyKeys.EC2_P384) {
      return new ECGenParameterSpec("secp384r1");
    }
    if (cnCurve == KeyKeys.EC2_P521) {
      return new ECGenParameterSpec("secp521r1");
    }
    throw new CoseException("Unsupported curve " + cnCurve);
  }

  public static COSEKey generateKey(AlgorithmID algorithm)
      throws CoseException {
    return generateKey(algorithm, null);
  }

  /**
   * Generate a random key pair based on the given algorithm. Some algorithm can take a parameter.
   * For example, the RSA_PSS family of algorithm can take the RSA key size as a parameter.
   *
   * @param algorithm the algorithm to generate a key pair for
   * @param parameters optional parameters to the key pair generator
   * @return the generated Key Pair
   * @throws CoseException
   */
  public static COSEKey generateKey(AlgorithmID algorithm, String parameters)
      throws CoseException {
    return generateKey(algorithm, parameters, null);
  }

  /**
   * Generate a random key pair based on the given algorithm. Some algorithm can take a parameter.
   * For example, the RSA_PSS family of algorithm can take the RSA key size as a parameter.
   *
   * @param algorithm the algorithm to generate a key pair for
   * @param parameters optional parameters to the key pair generator
   * @param provider JCA provider to use
   * @return the generated Key Pair
   * @throws CoseException
   */
  public static COSEKey generateKey(
      AlgorithmID algorithm,
      String parameters,
      Provider provider) throws CoseException {
    COSEKey returnThis;
    switch (algorithm) {
      case ECDSA_256:
        returnThis = generateECDSAKey("P-256", KeyKeys.EC2_P256, provider);
        break;
      case ECDSA_384:
        returnThis = generateECDSAKey("P-384", KeyKeys.EC2_P384, provider);
        break;
      case ECDSA_512:
        returnThis = generateECDSAKey("P-521", KeyKeys.EC2_P521, provider);
        break;
      case EDDSA:
        returnThis = generateOkpKey("Ed25519", KeyKeys.OKP_Ed25519, provider);
        break;
      case RSA_PSS_256:
      case RSA_PSS_384:
      case RSA_PSS_512:
        int keySize = 2048;
        if (parameters != null) {
          try {
            keySize = Integer.parseInt(parameters);
          } catch (NumberFormatException ignored) {
          }
        }
        returnThis = generateRSAKey(keySize, provider);
        break;
      default:
        throw new CoseException("Unknown algorithm");
    }

    returnThis.add(KeyKeys.Algorithm, algorithm.AsCBOR());
    return returnThis;
  }

  public static COSEKey generateKey(CBORObject curve) throws CoseException {
    return generateKey(curve, null);
  }

  public static COSEKey generateKey(CBORObject curve, Provider provider)
      throws CoseException {
    String curveName;
    COSEKey returnThis;

    switch (curve.AsInt32()) {
      case 1:
        curveName = "P-256";
        returnThis = generateECDHKey(curveName, curve, provider);
        return returnThis;
      case 2:
        curveName = "P-384";
        returnThis = generateECDHKey(curveName, curve, provider);
        return returnThis;
      case 3:
        curveName = "P-521";
        returnThis = generateECDHKey(curveName, curve, provider);
        return returnThis;
      case 6:
        curveName = "Ed25519";
        return generateOkpKey(curveName, curve, provider);
      case 7:
        curveName = "Ed448";
        return generateOkpKey(curveName, curve, provider);
      case 4:
        curveName = "X25519";
        return generateOkpKey(curveName, curve, provider);
      case 5:
        curveName = "X448";
        return generateOkpKey(curveName, curve, provider);
      default:
        throw new CoseException("Unknown curve");
    }
  }

  private static COSEKey generateECDHKey(
      String curveName,
      CBORObject curve,
      Provider provider) throws CoseException {
    try {
      int curveSize;

      switch (curveName) {
        case "P-256":
          curveName = "secp256r1";
          curveSize = 256;
          break;
        case "P-384":
          curveName = "secp384r1";
          curveSize = 384;
          break;
        case "P-521":
          curveName = "secp521r1";
          curveSize = 521;
          break;
        default:
          throw new CoseException("Internal Error");
      }

      ECGenParameterSpec paramSpec = new ECGenParameterSpec(curveName);
      KeyPairGenerator gen = provider != null
          ? KeyPairGenerator.getInstance("EC", provider)
          : KeyPairGenerator.getInstance("EC");
      gen.initialize(paramSpec);

      KeyPair keyPair = gen.genKeyPair();

      ECPoint pubPoint = ((ECPublicKey) keyPair.getPublic()).getW();

      byte[] rgbX = ArrayFromBigNum(pubPoint.getAffineX(), curveSize);
      byte[] rgbY = ArrayFromBigNum(pubPoint.getAffineY(), curveSize);
      byte[] rgbD = ArrayFromBigNum(
          ((ECPrivateKey) keyPair.getPrivate()).getS(),
          curveSize);

      COSEKey key = new COSEKey();

      key.add(KeyKeys.KeyType, KeyKeys.KeyType_EC2);
      key.add(KeyKeys.EC2_Curve, curve);
      key.add(KeyKeys.EC2_X, CBORObject.FromByteArray(rgbX));
      key.add(KeyKeys.EC2_Y, CBORObject.FromByteArray(rgbY));
      key.add(KeyKeys.EC2_D, CBORObject.FromByteArray(rgbD));
      key.publicKey = keyPair.getPublic();
      key.privateKey = keyPair.getPrivate();

      return key;
    } catch (NoSuchAlgorithmException e) {
      throw new CoseException("No provider for algorithm", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CoseException("THe curve is not supported", e);
    }
  }

  private static byte[] ArrayFromBigNum(BigInteger n, int curveSize) {
    byte[] rgb = new byte[(curveSize + 7) / 8];
    byte[] rgb2 = n.toByteArray();
    if (rgb.length == rgb2.length)
      return rgb2;
    if (rgb2.length > rgb.length) {
      System.arraycopy(rgb2, rgb2.length - rgb.length, rgb, 0, rgb.length);
    } else {
      System.arraycopy(rgb2, 0, rgb, rgb.length - rgb2.length, rgb2.length);
    }
    return rgb;
  }

  private static COSEKey generateECDSAKey(
      String curveName,
      CBORObject curve,
      Provider provider) throws CoseException {
    try {
      int curveSize;

      switch (curveName) {
        case "P-256":
          curveName = "secp256r1";
          curveSize = 256;
          break;
        case "P-384":
          curveName = "secp384r1";
          curveSize = 384;
          break;
        case "P-521":
          curveName = "secp521r1";
          curveSize = 521;
          break;
        default:
          throw new CoseException("Internal Error");
      }

      ECGenParameterSpec paramSpec = new ECGenParameterSpec(curveName);
      KeyPairGenerator gen = provider != null
          ? KeyPairGenerator.getInstance("EC", provider)
          : KeyPairGenerator.getInstance("EC");
      gen.initialize(paramSpec);

      KeyPair keyPair = gen.genKeyPair();

      ECPoint pubPoint = ((ECPublicKey) keyPair.getPublic()).getW();

      byte[] rgbX = ArrayFromBigNum(pubPoint.getAffineX(), curveSize);
      byte[] rgbY = ArrayFromBigNum(pubPoint.getAffineY(), curveSize);
      byte[] rgbD = ArrayFromBigNum(
          ((ECPrivateKey) keyPair.getPrivate()).getS(),
          curveSize);

      COSEKey key = new COSEKey();

      key.add(KeyKeys.KeyType, KeyKeys.KeyType_EC2);
      key.add(KeyKeys.EC2_Curve, curve);
      key.add(KeyKeys.EC2_X, CBORObject.FromByteArray(rgbX));
      key.add(KeyKeys.EC2_Y, CBORObject.FromByteArray(rgbY));
      key.add(KeyKeys.EC2_D, CBORObject.FromByteArray(rgbD));
      key.publicKey = keyPair.getPublic();
      key.privateKey = keyPair.getPrivate();

      return key;
    } catch (NoSuchAlgorithmException e) {
      throw new CoseException("No provider for algorithm", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CoseException("The curve is not supported", e);
    }
  }

  /**
   * Create a COSEKey object with only the public fields. Filters out the private key fields but
   * leaves all positive number labels and text labels along with negative number labels that are
   * public fields.
   *
   * @return public version of the key
   */
  public COSEKey PublicKey() {
    COSEKey newKey = new COSEKey();
    CBORObject val = this.get(KeyKeys.KeyType);
    if (val.equals(KeyKeys.KeyType_Octet)) {
      return null;
    } else if (val.equals(KeyKeys.KeyType_EC2)) {
      newKey.add(KeyKeys.EC2_Curve, get(KeyKeys.EC2_Curve));
      newKey.add(KeyKeys.EC2_X, get(KeyKeys.EC2_X));
      newKey.add(KeyKeys.EC2_Y, get(KeyKeys.EC2_Y));
    } else if (val.equals(KeyKeys.KeyType_OKP)) {
      newKey.add(KeyKeys.OKP_Curve, get(KeyKeys.OKP_Curve));
      newKey.add(KeyKeys.OKP_X, get(KeyKeys.OKP_X));
    } else if (val.equals(KeyKeys.KeyType_RSA)) {
      newKey.add(KeyKeys.RSA_N, get(KeyKeys.RSA_N));
      newKey.add(KeyKeys.RSA_E, get(KeyKeys.RSA_E));
    } else {
      return null;
    }

    // Allow them to use the same underlying public key object

    newKey.publicKey = publicKey;

    for (CBORObject obj : keyMap.getKeys()) {
      val = keyMap.get(obj);
      if (obj.getType() == CBORType.Integer) {
        if (obj.AsInt32() > 0) {
          newKey.add(obj, val);
        }
      } else if (obj.getType() == CBORType.TextString) {
        newKey.add(obj, val);
      }
    }
    return newKey;
  }

  /**
   * Encode to a byte string
   *
   * @return encoded object as bytes.
   */
  public byte[] EncodeToBytes() {
    return keyMap.EncodeToBytes();
  }

  /**
   * Return the key as a CBOR object
   *
   * @return The key
   */
  public CBORObject AsCBOR() {
    return keyMap;
  }

  /**
   * Return a java.security.PublicKey that is the same as the COSEKey key
   *
   * @return the key
   * @throws CoseException If there is a conversion error
   */
  public PublicKey AsPublicKey() throws CoseException {
    return publicKey;
  }

  /**
   * Return a java.security.PrivateKey that is the same as the COSEKey key
   *
   * @return the key
   * @throws CoseException if there is a conversion error
   */
  public PrivateKey AsPrivateKey() throws CoseException {
    return privateKey;
  }

  private Object UserData;

  /**
   * Return the user data field.
   *
   * The user data object allows for an application to associate a piece of arbitrary data with a
   * key and retrieve it later.
   *
   * @return the user data object
   */
  public Object getUserData() {
    return UserData;
  }

  /**
   * Set the user data field.
   *
   * The user data field allows for an application to associate a piece of arbitrary data with a key
   * and retrieve it later.
   *
   * @param newData Data field to be saved.
   */
  public void setUserData(Object newData) {
    UserData = newData;
  }

  private void CheckOkpKey() throws CoseException {
    boolean needPublic = false;
    CBORObject val;
    String algName;

    byte[] oid;
    CBORObject cn = this.get(KeyKeys.OKP_Curve);
    if (cn == KeyKeys.OKP_Ed25519) {
      oid = ASN1.Oid_Ed25519;
      algName = "EdDSA";
    } else if (cn == KeyKeys.OKP_Ed448) {
      oid = ASN1.Oid_Ed448;
      algName = "EdDSA";
    } else if (cn == KeyKeys.OKP_X25519) {
      oid = ASN1.Oid_X25519;
      algName = "EdDH";
    } else if (cn == KeyKeys.OKP_X448) {
      oid = ASN1.Oid_X448;
      algName = "ECDH";
    } else {
      throw new CoseException("Key has an unknown curve");
    }

    try {
      val = this.get(KeyKeys.OKP_D);
      if (val != null) {
        if (val.getType() != CBORType.ByteString)
          throw new CoseException(
              "Malformed key structure");
        try {
          byte[] privateKeyBytes = ASN1.EncodeOctetString(val.GetByteString());
          byte[] pkcs8 = ASN1.EncodePKCS8(
              ASN1.AlgorithmIdentifier(oid, null),
              privateKeyBytes,
              null);

          KeyFactory fact = cryptoContext.getProvider() != null
              ? KeyFactory.getInstance(algName, cryptoContext.getProvider())
              : KeyFactory.getInstance(algName, "EdDSA");
          KeySpec keyspec = new PKCS8EncodedKeySpec(pkcs8);

          privateKey = fact.generatePrivate(keyspec);
        } catch (NoSuchAlgorithmException e) {
          throw new CoseException("Unsupported Algorithm", e);
        } catch (InvalidKeySpecException e) {
          throw new CoseException("Invalid Private Key", e);
        }
      }

      val = this.get(KeyKeys.OKP_X);
      if (val == null) {
        if (privateKey == null)
          throw new CoseException(
              "Malformed key structure");
        else
          needPublic = true;
      } else if (val.getType() != CBORType.ByteString)
        throw new CoseException(
            "Malformed key structure");

      if (privateKey != null && needPublic) {
        privateKey.getEncoded();
        // todo: calculate (and populate) public from private
      }

      byte[] spki = null;

      if (spki == null) {
        byte[] rgbKey = this.get(KeyKeys.OKP_X).GetByteString();

        spki = ASN1.EncodeSubjectPublicKeyInfo(
            ASN1.AlgorithmIdentifier(oid, null),
            rgbKey);
      }

      KeyFactory fact = cryptoContext.getProvider() != null
          ? KeyFactory.getInstance("EdDSA", cryptoContext.getProvider())
          : KeyFactory.getInstance("EdDSA", "EdDSA");
      KeySpec keyspec = new X509EncodedKeySpec(spki);
      publicKey = fact.generatePublic(keyspec);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new CoseException("Algorithm unsupported", e);
    } catch (InvalidKeySpecException e) {
      throw new CoseException("Internal error on SPKI", e);
    }
  }

  private static COSEKey generateOkpKey(
      String curveName,
      CBORObject curve,
      Provider provider) throws CoseException {
    try {
      switch (curveName) {
        case "Ed25519":
          break;
        case "Ed448":
        case "X22519":
        case "X448":
          throw new CoseException("Algorithm not supported.");
        default:
          throw new CoseException("Internal Error");
      }

      EdDSAGenParameterSpec paramSpec = new EdDSAGenParameterSpec(curveName);
      KeyPairGenerator gen = provider != null
          ? KeyPairGenerator.getInstance("EdDSA", provider)
          : KeyPairGenerator.getInstance("EdDSA", "EdDSA");
      gen.initialize(paramSpec);

      KeyPair keyPair = gen.genKeyPair();

      byte[] rgbX = ((EdDSAPublicKey) keyPair.getPublic()).getAbyte();
      byte[] rgbD = ((EdDSAPrivateKey) keyPair.getPrivate()).getSeed();

      COSEKey key = new COSEKey();

      key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
      key.add(KeyKeys.OKP_Curve, curve);
      key.add(KeyKeys.OKP_X, CBORObject.FromByteArray(rgbX));
      key.add(KeyKeys.OKP_D, CBORObject.FromByteArray(rgbD));
      key.publicKey = keyPair.getPublic();
      key.privateKey = keyPair.getPrivate();

      return key;
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new CoseException("No provider for algorithm", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new CoseException("The curve is not supported", e);
    }
  }

  private void CheckRsaKey() throws CoseException {
    CBORObject n = this.get(KeyKeys.RSA_N); // modulus, positive int
    CBORObject e = this.get(KeyKeys.RSA_E); // public exponent, positive int
    CBORObject d = this.get(KeyKeys.RSA_D); // private exponent, positive int
    CBORObject p = this.get(KeyKeys.RSA_P); // the prime factor p of n
    CBORObject q = this.get(KeyKeys.RSA_Q); // the prime factor q of n
    CBORObject dP = this.get(KeyKeys.RSA_DP); // d mod (p - 1)
    CBORObject dQ = this.get(KeyKeys.RSA_DQ); // d mod (q - 1)
    CBORObject qInv = this.get(KeyKeys.RSA_QI); // CRT coefficient
    CBORObject other = this.get(KeyKeys.RSA_OTHER); // other prime info, contains map of (ri, di,
                                                    // ti)

    // Public key
    if (n != null && e != null) {
      if (n.getType() != CBORType.ByteString || e.getType() != CBORType.ByteString) {
        throw new CoseException("Malformed key structure");
      }

      RSAPublicKeySpec spec = new RSAPublicKeySpec(
          new BigInteger(1, n.GetByteString()),
          new BigInteger(1, e.GetByteString()));

      try {
        KeyFactory factory = cryptoContext.getProvider() != null
            ? KeyFactory.getInstance("RSA", cryptoContext.getProvider())
            : KeyFactory.getInstance("RSA");
        publicKey = factory.generatePublic(spec);
      } catch (NoSuchAlgorithmException ex) {
        throw new CoseException("No provider for algorithm", ex);
      } catch (InvalidKeySpecException ex) {
        throw new CoseException("Invalid Public Key", ex);
      }
    }

    // Private key
    if (n != null
        && e != null
        && d != null
        && p != null
        && q != null
        && dP != null
        && dQ != null
        && qInv != null) {
      if (n.getType() != CBORType.ByteString ||
          e.getType() != CBORType.ByteString ||
          d.getType() != CBORType.ByteString ||
          p.getType() != CBORType.ByteString ||
          q.getType() != CBORType.ByteString ||
          dP.getType() != CBORType.ByteString ||
          dQ.getType() != CBORType.ByteString ||
          qInv.getType() != CBORType.ByteString) {
        throw new CoseException("Malformed key structure");
      }

      RSAPrivateKeySpec privateKeySpec;
      if (other == null) {
        // Single prime private key
        privateKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger(1, n.GetByteString()),
            new BigInteger(1, e.GetByteString()),
            new BigInteger(1, d.GetByteString()),
            new BigInteger(1, p.GetByteString()),
            new BigInteger(1, q.GetByteString()),
            new BigInteger(1, dP.GetByteString()),
            new BigInteger(1, dQ.GetByteString()),
            new BigInteger(1, qInv.GetByteString()));
      } else {
        // Multi prime private key
        if (other.getType() != CBORType.Array) {
          throw new CoseException("Malformed key structure");
        }

        // Validate and build an array of other prime
        RSAOtherPrimeInfo[] others = new RSAOtherPrimeInfo[other.size()];
        for (int i = 0; i < other.size(); i++) {
          CBORObject object = other.get(i);

          if (object.getType() != CBORType.Map) {
            throw new CoseException("Malformed key structure");
          }

          CBORObject ri = object.get(KeyKeys.RSA__R_I.AsCBOR());
          CBORObject di = object.get(KeyKeys.RSA__D_I.AsCBOR());
          CBORObject ti = object.get(KeyKeys.RSA__T_I.AsCBOR());

          if (ri == null || di == null || ti == null) {
            throw new CoseException("Malformed key structure");
          }

          if (ri.getType() != CBORType.ByteString ||
              di.getType() != CBORType.ByteString ||
              ti.getType() != CBORType.ByteString) {
            throw new CoseException("Malformed key structure");
          }

          others[i] = new RSAOtherPrimeInfo(
              new BigInteger(1, ri.GetByteString()),
              new BigInteger(1, di.GetByteString()),
              new BigInteger(1, ti.GetByteString()));
        }

        privateKeySpec = new RSAMultiPrimePrivateCrtKeySpec(
            new BigInteger(1, n.GetByteString()),
            new BigInteger(1, e.GetByteString()),
            new BigInteger(1, d.GetByteString()),
            new BigInteger(1, p.GetByteString()),
            new BigInteger(1, q.GetByteString()),
            new BigInteger(1, dP.GetByteString()),
            new BigInteger(1, dQ.GetByteString()),
            new BigInteger(1, qInv.GetByteString()),
            others);
      }

      try {
        KeyFactory factory = cryptoContext.getProvider() != null
            ? KeyFactory.getInstance("RSA", cryptoContext.getProvider())
            : KeyFactory.getInstance("RSA");
        privateKey = factory.generatePrivate(privateKeySpec);
      } catch (NoSuchAlgorithmException ex) {
        throw new CoseException("No provider for algorithm", ex);
      } catch (InvalidKeySpecException ex) {
        throw new CoseException("Invalid Private Key", ex);
      }
    }
  }

  private static COSEKey generateRSAKey(int keySize, Provider provider)
      throws CoseException {
    try {
      KeyPairGenerator gen = provider != null
          ? KeyPairGenerator.getInstance("RSA", provider)
          : KeyPairGenerator.getInstance("RSA");
      gen.initialize(keySize);

      KeyPair keyPair = gen.genKeyPair();

      RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyPair.getPrivate();

      COSEKey key = new COSEKey();

      key.add(KeyKeys.KeyType, KeyKeys.KeyType_RSA);
      key.add(
          KeyKeys.RSA_N,
          CBORObject.FromByteArray(priv.getModulus().toByteArray()));
      key.add(
          KeyKeys.RSA_E,
          CBORObject.FromByteArray(priv.getPublicExponent().toByteArray()));
      key.add(
          KeyKeys.RSA_D,
          CBORObject.FromByteArray(priv.getPrivateExponent().toByteArray()));
      key.add(
          KeyKeys.RSA_P,
          CBORObject.FromByteArray(priv.getPrimeP().toByteArray()));
      key.add(
          KeyKeys.RSA_Q,
          CBORObject.FromByteArray(priv.getPrimeQ().toByteArray()));
      key.add(
          KeyKeys.RSA_DP,
          CBORObject.FromByteArray(priv.getPrimeExponentP().toByteArray()));
      key.add(
          KeyKeys.RSA_DQ,
          CBORObject.FromByteArray(priv.getPrimeExponentQ().toByteArray()));
      key.add(
          KeyKeys.RSA_QI,
          CBORObject.FromByteArray(priv.getCrtCoefficient().toByteArray()));

      key.publicKey = keyPair.getPublic();
      key.privateKey = keyPair.getPrivate();

      return key;
    } catch (NoSuchAlgorithmException e) {
      throw new CoseException("No provider for algorithm", e);
    }
  }
}
