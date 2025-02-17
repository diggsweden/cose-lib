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
 *
 * @author jimsch
 */
public class MACCOSEObject extends MacCommon {

  protected List<Recipient> recipientList = new ArrayList<>();

  public MACCOSEObject() {
    super();
    strContext = "MAC";
    coseObjectTag = COSEObjectTag.MAC;
  }

  public void addRecipient(Recipient recipient) throws CoseException {
    if (recipient == null)
      throw new CoseException("Recipient is null");
    recipientList.add(recipient);
  }

  public Recipient getRecipient(int iRecipient) {
    return recipientList.get(iRecipient);
  }

  public int getRecipientCount() {
    return recipientList.size();
  }

  public List<Recipient> getRecipientList() {
    return recipientList;
  }

  public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
    if (obj.size() != 5)
      throw new CoseException("Invalid MAC structure");

    if (obj.get(0).getType() == CBORType.ByteString) {
      if (obj.get(0).GetByteString().length == 0)
        objProtected =
            CBORObject.NewMap();
      else
        objProtected = CBORObject.DecodeFromBytes(
            obj.get(0).GetByteString());
    } else
      throw new CoseException("Invalid MAC structure");

    if (obj.get(1).getType() == CBORType.Map) {
      objUnprotected = obj.get(1);
    } else
      throw new CoseException("Invalid MAC structure");

    if (obj.get(2).getType() == CBORType.ByteString)
      rgbContent = obj
          .get(2)
          .GetByteString();
    else if (!obj.get(2).isNull())
      throw new CoseException(
          "Invalid MAC structure");

    if (obj.get(3).getType() == CBORType.ByteString)
      rgbTag = obj
          .get(3)
          .GetByteString();
    else
      throw new CoseException("Invalid MAC structure");

    if (obj.get(4).getType() == CBORType.Array) {
      for (int i = 0; i < obj.get(4).size(); i++) {
        Recipient recipient = new Recipient();
        recipient.DecodeFromCBORObject(obj.get(4).get(i));
        recipientList.add(recipient);
      }
    } else
      throw new CoseException("Invalid MAC structure");
  }

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

    CBORObject cnRecipients = CBORObject.NewArray();
    for (Recipient r : recipientList) {
      cnRecipients.Add(r.EncodeCBORObject());
    }
    obj.Add(cnRecipients);

    return obj;
  }

  public boolean Validate(Recipient recipientToUse)
      throws CoseException, Exception {
    byte[] rgbKey = null;
    AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));

    for (Recipient recipient : recipientList) {
      if (recipientToUse == null) {
        try {
          rgbKey = recipient.decrypt(alg, recipientToUse);
        } catch (CoseException e) {
          System.out.println(
              "This exception should likely be logged or handled ");
        }
      } else if (recipientToUse == recipient) {
        try {
          rgbKey = recipient.decrypt(alg, recipientToUse);
        } catch (CoseException e) {
          System.out.println(
              "This exception should likely be logged or handled ");
        }
        if (rgbKey == null)
          break;
      }

      if (rgbKey != null) {
        return super.Validate(rgbKey);
      }
    }
    throw new CoseException("Usable recipient not found");
  }

  public void Create() throws CoseException, IllegalStateException, Exception {
    AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
    byte[] rgbKey = null;

    int recipientTypes = 0;

    if (recipientList.isEmpty())
      throw new CoseException(
          "No recipients supplied");
    for (Recipient r : recipientList) {
      switch (r.getRecipientType()) {
        case 1:
          if ((recipientTypes & 1) != 0)
            throw new CoseException(
                "Cannot have two direct recipients");
          recipientTypes |= 1;
          rgbKey = r.getKey(alg);
          break;
        default:
          recipientTypes |= 2;
      }
    }

    if (recipientTypes == 3)
      throw new CoseException(
          "Do not mix direct and indirect recipients");

    if (recipientTypes == 2) {
      rgbKey = new byte[alg.getKeySize() / 8];
      random.nextBytes(rgbKey);
    }

    super.CreateWithKey(rgbKey);

    for (Recipient r : recipientList) {
      r.SetContent(rgbKey);
      r.encrypt();
    }
  }
}
