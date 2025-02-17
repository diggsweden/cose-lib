// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 *
 * @author Jim
 */
public class CounterSign1 extends Signer {

  public CounterSign1() {
    contextString = "CounterSignature0";
  }

  public CounterSign1(byte[] rgb) {
    contextString = "CounterSignature0";
    rgbSignature = rgb;
    rgbProtected = new byte[0];
  }

  public CounterSign1(COSEKey key) {
    super(key);
    contextString = "CounterSignature0";
    objUnprotected.Clear();
    objProtected.Clear();
  }

  public void setKey(COSEKey key) {
    cnKey = key;
  }

  @Override
  public void DecodeFromCBORObject(CBORObject cbor) throws CoseException {
    if (cbor.getType() != CBORType.ByteString) {
      throw new CoseException("Invalid format for Countersignature0");
    }

    rgbSignature = cbor.GetByteString();
    rgbProtected = new byte[0];
  }

  public CBORObject EncodeToCBORObject() throws CoseException {
    if (!objProtected.getValues().isEmpty() ||
        !objUnprotected.getValues().isEmpty()) {
      throw new CoseException(
          "CounterSign1 object cannot have protected or unprotected attributes");
    }

    return CBORObject.FromByteArray(rgbSignature);
  }
}
