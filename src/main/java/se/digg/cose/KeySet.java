// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import com.upokecenter.cbor.CBORObject;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 *
 * @author jimsch
 */
public class KeySet {

  private List<COSEKey> keys;

  public KeySet() {
    keys = new ArrayList<COSEKey>();
  }

  public KeySet(CBORObject keysIn) {
    keys = new ArrayList<COSEKey>();

    // Ignore keys which we cannot deal with or are malformed.

    for (int i = 0; i < keysIn.size(); i++) {
      try {
        keys.add(new COSEKey(keysIn.get(i)));
      } catch (CoseException e) {
        System.out.println("This exception should likely be logged or handled");
      }
    }
  }

  public void add(COSEKey key) {
    keys.add(key);
  }

  public List<COSEKey> getList() {
    return keys;
  }

  public void remove(COSEKey key) {
    keys.remove(key);
  }

  public Stream<COSEKey> stream() {
    return keys.stream();
  }

  public Stream<COSEKey> parallelStream() {
    return keys.parallelStream();
  }
}
