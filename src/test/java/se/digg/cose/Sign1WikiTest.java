// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import se.digg.cose.AlgorithmID;
import se.digg.cose.Attribute;
import se.digg.cose.COSEKey;
import se.digg.cose.COSEObject;
import se.digg.cose.CoseException;
import se.digg.cose.HeaderKeys;
import se.digg.cose.KeyKeys;
import se.digg.cose.Sign1COSEObject;

/**
 *
 * @author jimsch
 */
public class Sign1WikiTest extends TestBase {

  static COSEKey signingKey;
  static COSEKey sign2Key;
  static COSEKey sign3Key;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Before
  public void setUp() throws CoseException {
    signingKey = COSEKey.generateKey(AlgorithmID.ECDSA_256);
    sign2Key = COSEKey.generateKey(AlgorithmID.ECDSA_512);
    sign3Key = COSEKey.generateKey(AlgorithmID.ECDSA_384);
  }

  @Test
  public void testSignAMessage() throws CoseException {
    byte[] result = SignAMessage("This is lots of content");
    assert (VerifyAMessage(result, signingKey));
    assert (!VerifyAMessage(result, sign2Key));
  }

  public static byte[] SignAMessage(String ContentToSign) throws CoseException {
    //  Create the signed message
    Sign1COSEObject msg = new Sign1COSEObject();

    //  Add the content to the message
    msg.SetContent(ContentToSign);
    msg.addAttribute(
      HeaderKeys.Algorithm,
      signingKey.get(KeyKeys.Algorithm),
      Attribute.PROTECTED
    );

    //  Force the message to be signed
    msg.sign(signingKey);

    //  Now serialize out the message
    return msg.EncodeToBytes();
  }

  public static boolean VerifyAMessage(byte[] message, COSEKey key) {
    boolean result;

    try {
      Sign1COSEObject msg = (Sign1COSEObject) COSEObject.DecodeFromBytes(
        message
      );

      result = msg.validate(key);
    } catch (CoseException e) {
      return false;
    }

    return result;
  }
}
