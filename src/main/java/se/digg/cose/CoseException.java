// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

/**
 *
 * @author jimsch
 */
public class CoseException extends Exception {

  public CoseException(String message) {
    super(message);
  }

  public CoseException(String message, Exception ex) {
    super(message, ex);
  }
}
