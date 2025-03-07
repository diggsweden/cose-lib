// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author jimsch
 */
public class Sign1COSEObjectTest extends TestBase {

  static byte[] rgbContent = {
      'T',
      'h',
      'i',
      's',
      ' ',
      'i',
      's',
      ' ',
      's',
      'o',
      'm',
      'e',
      ' ',
      'c',
      'o',
      'n',
      't',
      'e',
      'n',
      't',
  };

  static COSEKey cnKeyPublic;
  static COSEKey cnKeyPublicCompressed;
  static COSEKey cnKeyPrivate;
  static ECPublicKeyParameters keyPublic;
  static ECPrivateKeyParameters keyPrivate;

  public Sign1COSEObjectTest() {}

  @BeforeClass
  public static void setUpClass() throws CoseException {
    X9ECParameters p = NISTNamedCurves.getByName("P-256");

    ECDomainParameters parameters = new ECDomainParameters(
        p.getCurve(),
        p.getG(),
        p.getN(),
        p.getH());
    ECKeyPairGenerator pGen = new ECKeyPairGenerator();
    ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(
        parameters,
        null);
    pGen.init(genParam);

    AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();

    keyPublic = (ECPublicKeyParameters) p1.getPublic();
    keyPrivate = (ECPrivateKeyParameters) p1.getPrivate();

    byte[] rgbX = keyPublic.getQ().normalize().getXCoord().getEncoded();
    byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();
    byte[] rgbD = keyPrivate.getD().toByteArray();

    CBORObject key = CBORObject.NewMap();
    key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
    key.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
    key.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
    key.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
    cnKeyPublic = new COSEKey(key);

    key = CBORObject.NewMap();
    key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
    key.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
    key.Add(KeyKeys.EC2_X.AsCBOR(), rgbX);
    key.Add(KeyKeys.EC2_Y.AsCBOR(), rgbY);
    cnKeyPublicCompressed = new COSEKey(key);

    key = CBORObject.NewMap();
    key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
    key.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
    key.Add(KeyKeys.EC2_D.AsCBOR(), rgbD);
    cnKeyPrivate = new COSEKey(key);
  }

  @AfterClass
  public static void tearDownClass() {}

  @Before
  public void setUp() {}

  @After
  public void tearDown() {}

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  /**
   * Test of Decrypt method, of class Encrypt0COSEObject.
   */
  @Test
  public void testRoundTrip() throws Exception {
    System.out.println("Round Trip");
    Sign1COSEObject msg = new Sign1COSEObject();
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.ECDSA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.sign(cnKeyPrivate);
    byte[] rgbMsg = msg.EncodeToBytes();

    msg = (Sign1COSEObject) COSEObject.DecodeFromBytes(
        rgbMsg,
        COSEObjectTag.Sign1);
    boolean f = msg.validate(cnKeyPublic);

    assert f;
  }

  /**
   * Test of Decrypt method, of class Encrypt0COSEObject.
   */
  @Test
  public void testRoundTripMixed() throws Exception {
    System.out.println("Round Trip");
    Sign1COSEObject msg = new Sign1COSEObject();
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.ECDSA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.sign(cnKeyPrivate);
    byte[] rgbMsg = msg.EncodeToBytes();

    msg = (Sign1COSEObject) COSEObject.DecodeFromBytes(
        rgbMsg,
        COSEObjectTag.Sign1);
    boolean f = msg.validate(cnKeyPublic);

    assert f;
  }

  @Test
  public void noAlgorithm() throws CoseException {
    Sign1COSEObject msg = new Sign1COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Algorithm Specified");
    msg.SetContent(rgbContent);
    msg.sign(cnKeyPrivate);
  }

  @Test
  public void unknownAlgorithm() throws CoseException {
    Sign1COSEObject msg = new Sign1COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unknown Algorithm Specified");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        CBORObject.FromString("Unknown"),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.sign(cnKeyPrivate);
  }

  @Test
  public void unsupportedAlgorithm() throws CoseException {
    Sign1COSEObject msg = new Sign1COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unsupported Algorithm Specified");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.HMAC_SHA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.sign(cnKeyPrivate);
  }

  @Test
  public void nullKey() throws CoseException {
    Sign1COSEObject msg = new Sign1COSEObject();
    COSEKey key = null;

    thrown.expect(NullPointerException.class);
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.ECDSA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.sign(key);
  }

  @Test
  public void noContent() throws CoseException {
    Sign1COSEObject msg = new Sign1COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Content Specified");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.ECDSA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.sign(cnKeyPrivate);
  }

  @Test
  public void publicKey() throws CoseException {
    Sign1COSEObject msg = new Sign1COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Private key required to sign");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.ECDSA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.sign(cnKeyPublic);
  }

  @Test
  public void decodeWrongBasis() throws CoseException {
    CBORObject obj = CBORObject.NewMap();

    thrown.expect(CoseException.class);
    thrown.expectMessage("COSEObject is not a COSE security COSEObject");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign1);
  }

  @Test
  public void codeWrongCount() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Sign1 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign1);
  }

  @Test
  public void decodeBadProtected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Sign1 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign1);
  }

  @Test
  public void decodeBadProtected2() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromByteArray(CBORObject.False.EncodeToBytes()));
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Sign1 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign1);
  }

  @Test
  public void decodeBadUnprotected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Sign1 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign1);
  }

  @Test
  public void decodeBadContent() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Sign1 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign1);
  }

  @Test
  public void decodeBadSignature() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(new byte[0]);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Sign1 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign1);
  }
}
