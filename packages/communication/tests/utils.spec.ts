import { describe, expect, it } from 'vitest';

import { decodeVersionedSignature, encodeVersionedSignature } from '../lib';

describe('encodeVersionedSignature', () => {
  /**
   * @target encodeVersionedSignature should prefix the raw signature with the version
   * @dependencies
   * @scenario
   * - call encodeVersionedSignature with a version and a raw signature
   * @expected
   * - must return `<version>:<raw signature>`
   */
  it('should prefix the raw signature with the version', () => {
    expect(encodeVersionedSignature('1.2.3', 'abcdef')).toEqual('1.2.3:abcdef');
  });
});

describe('decodeVersionedSignature', () => {
  /**
   * @target decodeVersionedSignature should return the version and raw signature
   * @dependencies
   * @scenario
   * - call decodeVersionedSignature with `<version>:<raw signature>`
   * @expected
   * - must return the version and raw signature
   */
  it('should return the version and raw signature', () => {
    expect(decodeVersionedSignature('1.2.3-beta.1:abcdef')).toEqual({
      version: '1.2.3-beta.1',
      rawSignature: 'abcdef',
    });
  });

  /**
   * @target decodeVersionedSignature should return undefined for malformed signatures
   * @dependencies
   * @scenario
   * - call decodeVersionedSignature with a signature without separator, with empty
   *   version, with empty raw signature, and with undefined
   * @expected
   * - must return undefined for all
   */
  it('should return undefined for malformed signatures', () => {
    expect(decodeVersionedSignature('abcdef')).toBeUndefined();
    expect(decodeVersionedSignature(':abcdef')).toBeUndefined();
    expect(decodeVersionedSignature('1.2.3:')).toBeUndefined();
    expect(decodeVersionedSignature(undefined)).toBeUndefined();
  });
});
