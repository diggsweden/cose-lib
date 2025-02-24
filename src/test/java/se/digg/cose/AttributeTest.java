// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import static org.junit.Assert.assertSame;

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
public class AttributeTest extends TestBase {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  public AttributeTest() {}

  @BeforeClass
  public static void setUpClass() {}

  @AfterClass
  public static void tearDownClass() {}

  @Before
  public void setUp() {}

  @After
  public void tearDown() {}

  @Test
  public void testAddAttribute_1() throws Exception {
    CBORObject label = CBORObject.FromByteArray(new byte[1]);
    CBORObject value = null;
    int where = Attribute.PROTECTED;
    Attribute instance = new Attribute();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Labels must be integers or strings");

    instance.addAttribute(label, value, where);
  }

  @Test
  public void testAddAttribute_2() throws Exception {
    CBORObject label = CBORObject.FromInt32(1);
    CBORObject value = CBORObject.FromInt32(2);
    int where = 0;
    Attribute instance = new Attribute();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid attribute location given");

    instance.addAttribute(label, value, where);
  }

  @Test
  public void testAddAttribute_3() throws Exception {
    byte[] rgbKey = new byte[256 / 8];
    MAC0COSEObject msg = new MAC0COSEObject();
    msg.SetContent("ABCDE");
    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.HMAC_SHA_256.AsCBOR(),
        Attribute.PROTECTED);
    msg.Create(rgbKey);

    thrown.expect(CoseException.class);
    thrown.expectMessage(
        "Operation would modify integrity protected attributes");

    msg.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_GCM_128.AsCBOR(),
        Attribute.PROTECTED);
  }

  @Test
  public void testAddAttribute_4() throws Exception {
    Attribute instance = new Attribute();

    instance.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_CBC_MAC_128_128.AsCBOR(),
        Attribute.PROTECTED);
    instance.addAttribute(
        HeaderKeys.CONTENT_TYPE,
        AlgorithmID.AES_CBC_MAC_128_64.AsCBOR(),
        Attribute.UNPROTECTED);
    instance.addAttribute(
        HeaderKeys.CounterSignature,
        AlgorithmID.AES_CBC_MAC_256_64.AsCBOR(),
        Attribute.DO_NOT_SEND);

    CBORObject cn;

    cn = instance.findAttribute(HeaderKeys.Algorithm, Attribute.PROTECTED);
    assertSame(cn, AlgorithmID.AES_CBC_MAC_128_128.AsCBOR());
    assert null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.UNPROTECTED);
    assert null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.DO_NOT_SEND);

    cn = instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.UNPROTECTED);
    assertSame(cn, AlgorithmID.AES_CBC_MAC_128_64.AsCBOR());
    assert null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.PROTECTED);
    assert null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.DO_NOT_SEND);

    cn = instance.findAttribute(
        HeaderKeys.CounterSignature,
        Attribute.DO_NOT_SEND);
    assertSame(cn, AlgorithmID.AES_CBC_MAC_256_64.AsCBOR());
    assert null == instance.findAttribute(HeaderKeys.CounterSignature, Attribute.UNPROTECTED);
    assert null == instance.findAttribute(HeaderKeys.CounterSignature, Attribute.PROTECTED);
  }

  @Test
  public void testAddAttribute_5() throws Exception {
    Attribute instance = new Attribute();

    instance.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_CBC_MAC_128_128.AsCBOR(),
        Attribute.PROTECTED);
    instance.addAttribute(
        HeaderKeys.CONTENT_TYPE,
        AlgorithmID.AES_CBC_MAC_128_64.AsCBOR(),
        Attribute.UNPROTECTED);

    instance.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.ECDSA_256.AsCBOR(),
        Attribute.PROTECTED);
    instance.addAttribute(
        HeaderKeys.CONTENT_TYPE,
        AlgorithmID.ECDH_ES_HKDF_256.AsCBOR(),
        Attribute.PROTECTED);

    CBORObject cn;

    cn = instance.findAttribute(HeaderKeys.Algorithm, Attribute.PROTECTED);
    assertSame(cn, AlgorithmID.ECDSA_256.AsCBOR());
    assert null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.UNPROTECTED);
    assert null == instance.findAttribute(HeaderKeys.Algorithm, Attribute.DO_NOT_SEND);

    cn = instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.PROTECTED);
    assertSame(cn, AlgorithmID.ECDH_ES_HKDF_256.AsCBOR());
    assert null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.UNPROTECTED);
    assert null == instance.findAttribute(HeaderKeys.CONTENT_TYPE, Attribute.DO_NOT_SEND);
  }

  @Test
  public void removeAttribute() throws Exception {
    Attribute instance = new Attribute();

    instance.addAttribute(
        HeaderKeys.Algorithm,
        AlgorithmID.AES_CBC_MAC_128_128.AsCBOR(),
        Attribute.PROTECTED);

    CBORObject cn;
    cn = instance.findAttribute(HeaderKeys.Algorithm);
    assertSame(cn, AlgorithmID.AES_CBC_MAC_128_128.AsCBOR());

    instance.removeAttribute(HeaderKeys.Algorithm);
    cn = instance.findAttribute(HeaderKeys.Algorithm);
    assert cn == null;
  }
}
