import { VersionedSignature } from './interfaces/types';

/**
 * extract the major and minor components of a semantic version string, e.g. `2` from
 * `2.0.2`. Two protocol versions are considered compatible when their
 * major component matches.
 * @param version
 */
export const getVersionSections = (version: string | undefined) => {
  const sections = (version ?? '').split('.');
  return {
    major: sections[0],
    minor: sections[1] ?? '',
  };
};

/**
 * prefix a raw signature with the protocol version it was produced with
 * @param version
 * @param rawSignature
 */
export const encodeVersionedSignature = (
  version: string,
  rawSignature: string,
) => `${version}:${rawSignature}`;

/**
 * split a `<version>:<raw signature>` signature into its parts
 * @param signature
 * @returns undefined if signature is malformed
 */
export const decodeVersionedSignature = (
  signature: string | undefined,
): VersionedSignature | undefined => {
  if (typeof signature !== 'string') return undefined;
  // raw signatures never contain ':', so split on the last one
  const separatorIndex = signature.lastIndexOf(':');
  if (separatorIndex === -1) return undefined;
  const version = signature.slice(0, separatorIndex);
  const rawSignature = signature.slice(separatorIndex + 1);
  if (version === '' || rawSignature === '') return undefined;
  return { version, rawSignature };
};
