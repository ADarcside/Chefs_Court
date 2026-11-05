import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import globals from "globals";

export default [
  { ignores: ["node_modules/", "uploads/", "coverage/"] },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: globals.node,
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "prefer-const": "error",
      eqeqeq: ["error", "always"],
    },
  },
  {
    // Playwright callbacks passed to page.evaluate run in the browser.
    files: ["scripts/demo/**"],
    languageOptions: { globals: { ...globals.node, ...globals.browser } },
  },
  prettier,
];
