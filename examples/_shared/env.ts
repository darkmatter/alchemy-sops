export const requiredEnvironment = (name: string): string => {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`Set ${name} before running this example`);
  }
  return value;
};
