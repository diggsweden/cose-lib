// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.upokecenter.cbor.CBORObject;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author jimsch
 */
public class SignCOSEObjectTest extends TestBase {

  public SignCOSEObjectTest() {}

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @BeforeClass
  public static void setUpClass() {}

  @AfterClass
  public static void tearDownClass() {}

  @Before
  public void setUp() {}

  @After
  public void tearDown() {}

  /**
   * Test of EncodeCBORObject method, of class SignCOSEObject.
   */
  @Ignore
  @Test
  public void testEncodeCBORObject() throws Exception {
    System.out.println("EncodeCBORObject");
    SignCOSEObject instance = new SignCOSEObject();
    CBORObject expResult = null;
    CBORObject result = instance.EncodeCBORObject();
    assertEquals(expResult, result);
    // TODO review the generated test code and remove the default call to fail.
    fail("The test case is a prototype.");
  }

  /**
   * Test of getSigner method, of class SignCOSEObject.
   */
  @Ignore
  @Test
  public void testGetSigner() {
    System.out.println("getSigner");
    int iSigner = 0;
    SignCOSEObject instance = new SignCOSEObject();
    Signer expResult = null;
    Signer result = instance.getSigner(iSigner);
    assertEquals(expResult, result);
    // TODO review the generated test code and remove the default call to fail.
    fail("The test case is a prototype.");
  }

  @Test
  public void testGetSignerCount() {
    SignCOSEObject msg = new SignCOSEObject();

    assertEquals(msg.getSignerCount(), 0);

    Signer r = new Signer();
    msg.AddSigner(r);
    assertEquals(msg.getSignerCount(), 1);
  }

  /**
   * Test of sign method, of class SignCOSEObject.
   */
  @Ignore
  @Test
  public void testSign() throws CoseException {
    System.out.println("sign");
    SignCOSEObject instance = new SignCOSEObject();
    instance.sign();
    // TODO review the generated test code and remove the default call to fail.
    fail("The test case is a prototype.");
  }

  /**
   * Test of validate method, of class SignCOSEObject.
   */
  @Ignore
  @Test
  public void testValidate() throws CoseException {
    System.out.println("validate");
    Signer signerToUse = null;
    SignCOSEObject instance = new SignCOSEObject();
    boolean expResult = false;
    boolean result = instance.validate(signerToUse);
    assertEquals(expResult, result);
    // TODO review the generated test code and remove the default call to fail.
    fail("The test case is a prototype.");
  }

  @Test
  public void signDecodeWrongBasis() throws CoseException {
    CBORObject obj = CBORObject.NewMap();

    thrown.expect(CoseException.class);
    thrown.expectMessage("COSEObject is not a COSE security COSEObject");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign);
  }

  @Test
  public void signDecodeWrongCount() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid SignCOSEObject structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign);
  }

  @Test
  public void signDecodeBadProtected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid SignCOSEObject structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign);
  }

  @Test
  public void signDecodeBadProtected2() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid SignCOSEObject structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign);
  }

  @Test
  public void signDecodeBadUnprotected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid SignCOSEObject structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign);
  }

  @Test
  public void signDecodeBadContent() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid SignCOSEObject structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign);
  }

  @Test
  public void signDecodeBadRecipients() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.NewArray()).EncodeToBytes();
    obj.Add(CBORObject.NewMap());
    obj.Add(new byte[0]);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid SignCOSEObject structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Sign);
  }
}
