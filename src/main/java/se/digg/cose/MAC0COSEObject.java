// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 *
 * @author jimsch
 */
public class MAC0COSEObject extends MacCommon {

  public MAC0COSEObject() {
    super();
    strContext = "MAC0";
    coseObjectTag = COSEObjectTag.MAC0;
  }

  @Override
  public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
    if (obj.size() != 4)
      throw new CoseException("Invalid MAC0 structure");

    if (obj.get(0).getType() == CBORType.ByteString) {
      if (obj.get(0).GetByteString().length == 0)
        objProtected =
            CBORObject.NewMap();
      else
        objProtected = CBORObject.DecodeFromBytes(
            obj.get(0).GetByteString());
    } else
      throw new CoseException("Invalid MAC0 structure");

    if (obj.get(1).getType() == CBORType.Map) {
      objUnprotected = obj.get(1);
    } else
      throw new CoseException("Invalid MAC0 structure");

    if (obj.get(2).getType() == CBORType.ByteString)
      rgbContent = obj
          .get(2)
          .GetByteString();
    else if (!obj.get(2).isNull())
      throw new CoseException(
          "Invalid MAC0 structure");

    if (obj.get(3).getType() == CBORType.ByteString)
      rgbTag = obj
          .get(3)
          .GetByteString();
    else
      throw new CoseException("Invalid MAC0 structure");
  }

  @Override
  protected CBORObject EncodeCBORObject() throws CoseException {
    if (rgbTag == null)
      throw new CoseException("Compute function not called");

    CBORObject obj = CBORObject.NewArray();
    if (objProtected.size() > 0)
      obj.Add(objProtected.EncodeToBytes());
    else
      obj.Add(CBORObject.FromByteArray(new byte[0]));

    obj.Add(objUnprotected);
    obj.Add(rgbContent);
    obj.Add(rgbTag);

    return obj;
  }

  public void Create(byte[] rgbKey) throws CoseException {
    super.CreateWithKey(rgbKey);
  }

  @Override
  public boolean Validate(byte[] rgbKey) throws CoseException {
    return super.Validate(rgbKey);
  }
}
