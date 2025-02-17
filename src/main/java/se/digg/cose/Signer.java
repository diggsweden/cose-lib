// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.ArrayList;
import java.util.List;

/**
 * The Signer class is used to implement the COSE_Signer object. This provides the information
 * dealing with a single signature for the SignCOSEObject class.
 * <p>
 * Create a Signer object for adding a new signature to a message, existing signers will have a
 * Signer object created for them when a SignCOSEObject object is created by
 * COSEObject.DecodeFromBytes.
 * <p>
 * Examples of using this class can be found in <br>
 * <a href="https://github.com/cose-wg/COSE-JAVA/wiki/Sign-Message-Example">Single Signer
 * Example</a> an example of signing and verify a message with a single signature. <br>
 * <a href="https://github.com/cose-wg/COSE-JAVA/wiki/Multi-Sign-Example">Multiple Signer
 * Example</a> an example of signing and verifying a message which has multiple signatures.
 *
 * @author jimsch
 */
public class Signer extends Attribute {

  protected byte[] rgbSignature;
  protected String contextString;
  COSEKey cnKey;

  /**
   * Create a new signer object to add to a SignCOSEObject
   */
  public Signer() {
    contextString = "Signature";
  }

  /**
   * Create a new signer object for a SignCOSEObject and set the key to be used.
   *
   * @param key key to use for signing.
   */
  public Signer(COSEKey key) {
    contextString = "Signature";
    cnKey = key;
  }

  /**
   * Remove the key object from the signer
   *
   * @since COSE 0.9.1
   */
  public void clearKey() {
    cnKey = null;
  }

  /**
   * Set a key object on a signer
   *
   * @since COSE 0.9.1
   * @param keyIn key to be used for signing or verification
   * @throws CoseException - Invalid key passed in
   */
  public void setKey(COSEKey keyIn) throws CoseException {
    setupKey(keyIn);
  }

  /**
   * Set the key on the object, if there is not a signature on this object then set the algorithm
   * and the key id from the key if they exist on the key and do not exist in the message.
   *
   * @param key key to be used]
   */
  private void setupKey(COSEKey key) throws CoseException {
    CBORObject cn2;
    CBORObject cn;

    cnKey = key;

    if (rgbSignature != null)
      return;

    cn = key.get(KeyKeys.Algorithm);
    if (cn != null) {
      cn2 = findAttribute(HeaderKeys.Algorithm);
      if (cn2 == null)
        addAttribute(
            HeaderKeys.Algorithm,
            cn,
            Attribute.PROTECTED);
    }

    cn = key.get(KeyKeys.KeyId);
    if (cn != null) {
      cn2 = findAttribute(HeaderKeys.KID);
      if (cn2 == null)
        addAttribute(HeaderKeys.KID, cn, Attribute.UNPROTECTED);
    }
  }

  /**
   * Internal function used in creating a Sign1COSEObject object from a byte string.
   *
   * @param obj COSE_Sign1 encoded object.
   * @throws CoseException Errors generated by the COSE module
   */
  protected void DecodeFromCBORObject(CBORObject obj) throws CoseException {
    if (obj.getType() != CBORType.Array)
      throw new CoseException(
          "Invalid Signer structure");

    if (obj.size() != 3)
      throw new CoseException("Invalid Signer structure");

    if (obj.get(0).getType() == CBORType.ByteString) {
      rgbProtected = obj.get(0).GetByteString();
      if (rgbProtected.length == 0) {
        objProtected = CBORObject.NewMap();
      } else {
        objProtected = CBORObject.DecodeFromBytes(rgbProtected);
        if (objProtected.size() == 0)
          rgbProtected = new byte[0];
      }
    } else
      throw new CoseException("Invalid Signer structure");

    if (obj.get(1).getType() == CBORType.Map) {
      objUnprotected = obj.get(1);
    } else
      throw new CoseException("Invalid Signer structure");

    if (obj.get(2).getType() == CBORType.ByteString)
      rgbSignature = obj
          .get(2)
          .GetByteString();
    else if (!obj.get(2).isNull())
      throw new CoseException(
          "Invalid Signer structure");

    CBORObject countersignature =
        this.findAttribute(HeaderKeys.CounterSignature, UNPROTECTED);
    if (countersignature != null) {
      if ((countersignature.getType() != CBORType.Array) ||
          countersignature.getValues().isEmpty()) {
        throw new CoseException("Invalid countersignature attribute");
      }

      if (countersignature.get(0).getType() == CBORType.Array) {
        for (CBORObject csObj : countersignature.getValues()) {
          if (csObj.getType() != CBORType.Array) {
            throw new CoseException("Invalid countersignature attribute");
          }

          CounterSign cs = new CounterSign(csObj);
          this.addCountersignature(cs);
        }
      } else {
        CounterSign cs = new CounterSign(countersignature);
        this.addCountersignature(cs);
      }
    }

    countersignature = this.findAttribute(
        HeaderKeys.CounterSignature0,
        UNPROTECTED);
    if (countersignature != null) {
      if (countersignature.getType() != CBORType.ByteString) {
        throw new CoseException("Invalid Countersignature0 attribute");
      }

      CounterSign1 cs = new CounterSign1(countersignature.GetByteString());
      this.counterSign1 = cs;
    }
  }

  /**
   * Internal function used to create a serialization of a COSE_Sign1 message
   *
   * @return CBOR object which can be encoded.
   * @throws CoseException Errors generated by the COSE module
   */

  protected CBORObject EncodeToCBORObject() throws CoseException {
    if (rgbSignature == null)
      throw new CoseException(
          "COSEObject not yet signed");
    if (rgbProtected == null)
      throw new CoseException("Internal Error");
    CBORObject obj = CBORObject.NewArray();

    obj.Add(rgbProtected);
    obj.Add(objUnprotected);
    obj.Add(rgbSignature);

    return obj;
  }

  public void sign(byte[] rgbBodyProtected, byte[] rgbContent)
      throws CoseException {
    if (rgbProtected == null) {
      if (objProtected.size() == 0)
        rgbProtected = new byte[0];
      else
        rgbProtected = objProtected.EncodeToBytes();
    }

    CBORObject obj = CBORObject.NewArray();
    obj.Add(contextString);
    obj.Add(rgbBodyProtected);
    obj.Add(rgbProtected);
    obj.Add(externalData);
    obj.Add(rgbContent);

    AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));

    rgbSignature = SignCommon.computeSignature(alg, obj.EncodeToBytes(), cnKey);

    ProcessCounterSignatures();
  }

  public boolean validate(byte[] rgbBodyProtected, byte[] rgbContent)
      throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(contextString);
    obj.Add(rgbBodyProtected);
    obj.Add(rgbProtected);
    obj.Add(externalData);
    obj.Add(rgbContent);

    AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));

    return SignCommon.validateSignature(
        alg,
        obj.EncodeToBytes(),
        rgbSignature,
        cnKey);
  }

  List<CounterSign> counterSignList = new ArrayList<CounterSign>();
  CounterSign1 counterSign1;

  public void addCountersignature(CounterSign countersignature) {
    counterSignList.add(countersignature);
  }

  public List<CounterSign> getCountersignerList() {
    return counterSignList;
  }

  public CounterSign1 getCountersign1() {
    return counterSign1;
  }

  public void setCountersign1(CounterSign1 value) {
    counterSign1 = value;
  }

  protected void ProcessCounterSignatures() throws CoseException {
    if (!counterSignList.isEmpty()) {
      if (counterSignList.size() == 1) {
        counterSignList.get(0).sign(rgbProtected, rgbSignature);
        addAttribute(
            HeaderKeys.CounterSignature,
            counterSignList.get(0).EncodeToCBORObject(),
            Attribute.UNPROTECTED);
      } else {
        CBORObject list = CBORObject.NewArray();
        for (CounterSign sig : counterSignList) {
          sig.sign(rgbProtected, rgbSignature);
          list.Add(sig.EncodeToCBORObject());
        }
        addAttribute(HeaderKeys.CounterSignature, list, Attribute.UNPROTECTED);
      }
    }

    if (counterSign1 != null) {
      counterSign1.sign(rgbProtected, rgbSignature);
      addAttribute(
          HeaderKeys.CounterSignature0,
          counterSign1.EncodeToCBORObject(),
          Attribute.UNPROTECTED);
    }
  }

  public boolean validate(CounterSign1 countersignature) throws CoseException {
    return countersignature.validate(rgbProtected, rgbSignature);
  }

  public boolean validate(CounterSign countersignature) throws CoseException {
    return countersignature.validate(rgbProtected, rgbSignature);
  }
}
