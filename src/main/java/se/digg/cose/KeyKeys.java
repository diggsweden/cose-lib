// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import com.upokecenter.cbor.CBORObject;

/**
 *
 * @author jimsch
 */
public enum KeyKeys {
  KeyType(1),
  Algorithm(3),
  KeyId(2),
  Key_Ops(4),
  Base_IV(5),

  Octet_K(-1),

  EC2_Curve(-1),
  EC2_X(-2),
  EC2_Y(-3),
  EC2_D(-4),

  OKP_Curve(-1),
  OKP_X(-2),
  OKP_D(-4),

  RSA_N(-1),
  RSA_E(-2),
  RSA_D(-3),
  RSA_P(-4),
  RSA_Q(-5),
  RSA_DP(-6),
  RSA_DQ(-7),
  RSA_QI(-8),
  RSA_OTHER(-9),
  RSA__R_I(-10),
  RSA__D_I(-11),
  RSA__T_I(-12);

  private final CBORObject value;

  public static final CBORObject KeyType_OKP = CBORObject.FromInt32(1);
  public static final CBORObject KeyType_EC2 = CBORObject.FromInt32(2);
  public static final CBORObject KeyType_Octet = CBORObject.FromInt32(4);
  public static final CBORObject KeyType_RSA = CBORObject.FromInt32(3);

  public static final CBORObject EC2_P256 = CBORObject.FromInt32(1);
  public static final CBORObject EC2_P384 = CBORObject.FromInt32(2);
  public static final CBORObject EC2_P521 = CBORObject.FromInt32(3);

  public static final CBORObject OKP_X25519 = CBORObject.FromInt32(4);
  public static final CBORObject OKP_X448 = CBORObject.FromInt32(5);
  public static final CBORObject OKP_Ed25519 = CBORObject.FromInt32(6);
  public static final CBORObject OKP_Ed448 = CBORObject.FromInt32(7);

  KeyKeys(int val) {
    this.value = CBORObject.FromInt32(val);
  }

  public CBORObject AsCBOR() {
    return value;
  }
}
