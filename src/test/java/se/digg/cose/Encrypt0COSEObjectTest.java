// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import static org.junit.Assert.assertArrayEquals;

import com.upokecenter.cbor.CBORObject;
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
public class Encrypt0COSEObjectTest extends TestBase {

  byte[] rgbKey128 = {
      'a',
      'b',
      'c',
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
  };
  byte[] rgbKey256 = {
      'a',
      'b',
      'c',
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
      17,
      18,
      19,
      20,
      21,
      22,
      23,
      24,
      25,
      26,
      27,
      28,
      29,
      30,
      31,
      32,
  };
  byte[] rgbContent = {
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
  byte[] rgbIV128 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  byte[] rgbIV96 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

  public Encrypt0COSEObjectTest() {}

  @BeforeClass
  public static void setUpClass() {}

  @AfterClass
  public static void tearDownClass() {}

  @Before
  public void setUp() {}

  @After
  public void tearDown() {}

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  /**
   * Test of decrypt method, of class Encrypt0COSEObject.
   */
  @Test
  public void testRoundTrip() throws Exception {
    System.out.println("Round Trip");
    Encrypt0COSEObject msg = new Encrypt0COSEObject();
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.addAttribute(
        HeaderKeys.IV,
        CBORObject.FromByteArray(rgbIV96),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
    byte[] rgbMsg = msg.EncodeToBytes();

    msg = (Encrypt0COSEObject) COSEObject.DecodeFromBytes(
        rgbMsg,
        COSEObjectTag.Encrypt0);
    byte[] contentNew = msg.decrypt(rgbKey128);

    assertArrayEquals(rgbContent, contentNew);
  }

  @Test
  public void encryptNoAlgorithm() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Algorithm Specified");
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
  }

  @Test
  public void encryptUnknownAlgorithm() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unknown Algorithm Specified");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        CBORObject.FromString("Unknown"),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
  }

  @Test
  public void encryptUnsupportedAlgorithm() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unsupported Algorithm Specified");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.HMAC_SHA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
  }

  @Test
  public void encryptIncorrectKeySize() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Key Size is incorrect");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey256);
  }

  @Test
  public void encryptNullKey() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(NullPointerException.class);
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(null);
  }

  @Test
  public void encryptNoContent() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Content Specified");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.encrypt(rgbKey128);
  }

  @Test
  public void encryptBadIV() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("IV is incorrectly formed");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.addAttribute(
        HeaderKeys.IV,
        CBORObject.FromString("IV"),
        Attribute.UNPROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
  }

  @Test
  public void encryptIncorrectIV() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("IV size is incorrect");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.addAttribute(HeaderKeys.IV, rgbIV128, Attribute.UNPROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
  }

  @Test
  public void encryptNoTag() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject(false, true);

    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.addAttribute(
        HeaderKeys.IV,
        CBORObject.FromByteArray(rgbIV96),
        Attribute.PROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
    CBORObject cn = msg.EncodeCBORObject();

    assert !cn.isTagged();
  }

  @Test
  public void encryptNoEmitContent() throws CoseException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject(true, false);

    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.addAttribute(
        HeaderKeys.IV,
        CBORObject.FromByteArray(rgbIV96),
        Attribute.UNPROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);
    CBORObject cn = msg.EncodeCBORObject();

    assert cn.get(2).isNull();
  }

  @Test
  public void noContentForDecrypt()
      throws CoseException, IllegalStateException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject(true, false);

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Encrypted Content Specified");

    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.addAttribute(
        HeaderKeys.IV,
        CBORObject.FromByteArray(rgbIV96),
        Attribute.UNPROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);

    byte[] rgb = msg.EncodeToBytes();

    msg = (Encrypt0COSEObject) COSEObject.DecodeFromBytes(rgb);
    msg.decrypt(rgbKey128);
  }

  @Test
  public void roundTripDetached() throws CoseException, IllegalStateException {
    Encrypt0COSEObject msg = new Encrypt0COSEObject(true, false);

    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
    msg.addAttribute(
        HeaderKeys.IV,
        CBORObject.FromByteArray(rgbIV96),
        Attribute.UNPROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt(rgbKey128);

    byte[] content = msg.getEncryptedContent();

    byte[] rgb = msg.EncodeToBytes();

    msg = (Encrypt0COSEObject) COSEObject.DecodeFromBytes(rgb);
    msg.setEncryptedContent(content);
    msg.decrypt(rgbKey128);
  }

  @Test
  public void encryptWrongBasis() throws CoseException {
    CBORObject obj = CBORObject.NewMap();

    thrown.expect(CoseException.class);
    thrown.expectMessage("COSEObject is not a COSE security COSEObject");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt0);
  }

  @Test
  public void encryptDecodeWrongCount() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt0);
  }

  @Test
  public void encryptDecodeBadProtected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt0);
  }

  @Test
  public void encryptDecodeBadProtected2() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt0);
  }

  @Test
  public void encryptDecodeBadUnprotected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt0);
  }

  @Test
  public void encryptDecodeBadContent() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt0);
  }

  @Test
  public void encryptDecodeBadTag() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(new byte[0]);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt0);
  }
}
