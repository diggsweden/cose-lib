// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 diggsweden/cose-lib
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import java.security.Provider;
import java.security.Security;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 *
 * @author linuxwolf
 */
public abstract class TestBase {

  private static final Provider PROVIDER = new BouncyCastleProvider();
  private static final Provider EdDSA = new EdDSASecurityProvider();

  @BeforeClass
  public static void installProvider() throws Exception {
    Security.insertProviderAt(PROVIDER, 1);
    Security.insertProviderAt(EdDSA, 0);
  }

  @AfterClass
  public static void uninstallProvider() throws Exception {
    Security.removeProvider(PROVIDER.getName());
    Security.removeProvider(EdDSA.getName());
  }
}
