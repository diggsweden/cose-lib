// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import static org.junit.Assert.assertTrue;

import com.upokecenter.cbor.CBORObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author jimsch
 */
public class MAC0COSEObjectTest extends TestBase {

  static byte[] rgbKey128 = {
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
  static byte[] rgbKey256 = {
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

  CBORObject cnKey256;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  public MAC0COSEObjectTest() {}

  @Before
  public void setUp() {
    cnKey256 = CBORObject.NewMap();
    cnKey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
    cnKey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromByteArray(rgbKey256));
  }

  @After
  public void tearDown() {}

  /**
   * Test of Decrypt method, of class Encrypt0COSEObject.
   */

  @Test
  public void testRoundTrip() throws Exception {
    System.out.println("Round Trip");
    MAC0COSEObject msg = new MAC0COSEObject();
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.HMAC_SHA_256.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.SetContent(rgbContent);
    msg.Create(rgbKey256);

    byte[] rgbMsg = msg.EncodeToBytes();

    msg = (MAC0COSEObject) COSEObject.DecodeFromBytes(
      rgbMsg,
      COSEObjectTag.MAC0
    );
    boolean contentNew = msg.Validate(rgbKey256);
    assertTrue(contentNew);
  }

  @Test
  public void macNoAlgorithm() throws CoseException, Exception {
    MAC0COSEObject msg = new MAC0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Algorithm Specified");
    msg.SetContent(rgbContent);
    msg.Create(rgbKey256);
  }

  @Test
  public void macUnknownAlgorithm() throws CoseException, Exception {
    MAC0COSEObject msg = new MAC0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unknown Algorithm Specified");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      CBORObject.FromString("Unknown"),
      Attribute.PROTECTED
    );
    msg.SetContent(rgbContent);
    msg.Create(rgbKey256);
  }

  @Test
  public void macUnsupportedAlgorithm() throws CoseException, Exception {
    MAC0COSEObject msg = new MAC0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unsupported MAC Algorithm");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.AES_CCM_16_64_256.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.SetContent(rgbContent);
    msg.Create(rgbKey256);
  }

  @Test
  public void macNoContent() throws CoseException, Exception {
    MAC0COSEObject msg = new MAC0COSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Content Specified");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.HMAC_SHA_256.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.Create(rgbKey256);
  }

  @Test
  public void macDecodeWrongBasis() throws CoseException {
    CBORObject obj = CBORObject.NewMap();

    thrown.expect(CoseException.class);
    thrown.expectMessage("COSEObject is not a COSE security COSEObject");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.MAC0);
  }

  @Test
  public void macDecodeWrongCount() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid MAC0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.MAC0);
  }

  @Test
  public void macDecodeBadProtected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid MAC0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.MAC0);
  }

  @Test
  public void macDecodeBadProtected2() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid MAC0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.MAC0);
  }

  @Test
  public void macDecodeBadUnprotected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid MAC0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.MAC0);
  }

  @Test
  public void macDecodeBadContent() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid MAC0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.MAC0);
  }

  @Test
  public void macDecodeBadRecipients() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(new byte[0]);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid MAC0 structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.MAC0);
  }
}
