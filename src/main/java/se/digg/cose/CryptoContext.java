// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import java.security.Provider;

/**
 * Specify which JCA Provider to use for signing and verifying messages.
 */
public class CryptoContext {

  private Provider provider;

  public CryptoContext(Provider provider) {
    this.provider = provider;
  }

  public Provider getProvider() {
    return provider;
  }

  public void setProvider(Provider provider) {
    this.provider = provider;
  }
}
