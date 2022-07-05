const { resolve } = require("path");
const { pathsToModuleNameMapper } = require("ts-jest");

const pkg = require("./package.json");
const tsconfig = require("./tests/tsconfig.json");
const CI = !!process.env.CI;

module.exports = () => {
  return {
    preset: "ts-jest/presets/default-esm",
    globals: {
      "ts-jest": {
        tsconfig: "./tests/tsconfig.json",
      },
    },
    displayName: pkg.name,
    rootDir: __dirname,
    testEnvironment: "miniflare",
    testEnvironmentOptions: {
      kvNamespaces: ["TEST_NAMESPACE"],
    },
    restoreMocks: true,
    reporters: ["default"],
    modulePathIgnorePatterns: ["dist"],
    moduleNameMapper: pathsToModuleNameMapper(
      tsconfig.compilerOptions.paths || [],
      {
        prefix: `./`,
      }
    ),
    cacheDirectory: resolve(
      __dirname,
      `${CI ? "" : "node_modules/"}.cache/jest`
    ),
    collectCoverage: false,
  };
};
