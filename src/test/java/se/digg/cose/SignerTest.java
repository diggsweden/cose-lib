// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import static org.junit.Assert.*;

import com.upokecenter.cbor.CBORObject;
import org.junit.*;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import se.digg.cose.COSEKey;
import se.digg.cose.CoseException;
import se.digg.cose.Signer;

/**
 *
 * @author jimsch
 */
public class SignerTest extends TestBase {

  public SignerTest() {}

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
   * Test of setKey method, of class Signer.
   */
  @Ignore
  @Test
  public void testSetKey() throws CoseException {
    System.out.println("setKey");
    COSEKey cnKey = null;
    Signer instance = new Signer();
    instance.setKey(cnKey);
    // TODO review the generated test code and remove the default call to fail.
    fail("The test case is a prototype.");
  }

  @Test
  public void signerDecodeWrongBasis() throws CoseException {
    CBORObject obj = CBORObject.NewMap();

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Signer structure");

    Signer sig = new Signer();
    sig.DecodeFromCBORObject(obj);
  }

  @Test
  public void signerDecodeWrongCount() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Signer structure");

    Signer sig = new Signer();
    sig.DecodeFromCBORObject(obj);
  }

  @Test
  public void signerDecodeBadProtected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Signer structure");

    Signer sig = new Signer();
    sig.DecodeFromCBORObject(obj);
  }

  @Test
  public void signerDecodeBadProtected2() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromObject(CBORObject.False));
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Signer structure");

    Signer sig = new Signer();
    sig.DecodeFromCBORObject(obj);
  }

  @Test
  public void signerDecodeBadUnprotected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Signer structure");

    Signer sig = new Signer();
    sig.DecodeFromCBORObject(obj);
  }

  @Test
  public void signerDecodeBadSignature() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
    obj.Add(CBORObject.NewMap());
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Signer structure");

    Signer sig = new Signer();
    sig.DecodeFromCBORObject(obj);
  }
}
