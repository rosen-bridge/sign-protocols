export class ConfigError extends Error {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(configPath: string, actualValue: any) {
    super(
      `unexpected config at path ${configPath}: ${JSON.stringify(actualValue)}`,
    );
  }
}

export class NotStartedDialerNodeError extends Error {
  constructor() {
    super("Dialer node isn't ready, please try later");
  }
}
