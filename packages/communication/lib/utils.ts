/**
 * extract the major and minor components of a semantic version string, e.g. `2` from
 * `2.0.2`. Two protocol versions are considered compatible when their
 * major component matches.
 * @param version
 */
export const getVersionSections = (version: string) => {
  const sections = version.split('.');
  return {
    major: sections[0],
    minor: sections[1] ?? '',
  };
};
