// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import java.util.Collections;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

public class KeySetCollector implements Collector<COSEKey, KeySet, KeySet> {

  @Override
  public Supplier<KeySet> supplier() {
    return KeySet::new;
  }

  @Override
  public BiConsumer<KeySet, COSEKey> accumulator() {
    return (acc, elem) -> acc.add(elem);
  }

  @Override
  public BinaryOperator<KeySet> combiner() {
    // parallel streams are not supported
    return (acc1, acc2) -> {
      throw new UnsupportedOperationException(
          "parallel streams are not supported");
    };
  }

  @Override
  public Function<KeySet, KeySet> finisher() {
    return acc -> acc;
  }

  @Override
  public Set<Collector.Characteristics> characteristics() {
    return Collections.emptySet();
  }
}
