import { describe, it, expect } from "vitest";
import type { ConfigFile } from "../../src/types.js";
import {
  getFileContext,
  isInsideCodeFenceAt,
  lineNumberAt,
} from "../../src/rules/file-context.js";

function makeFile(content: string, path = "CLAUDE.md"): ConfigFile {
  return { path, type: "claude-md", content };
}

describe("lineNumberAt", () => {
  const file = makeFile("text\n```\ncode here\n```\nafter");

  it("returns 1-based line numbers", () => {
    expect(lineNumberAt(file, 0)).toBe(1);
    expect(lineNumberAt(file, 9)).toBe(3);
    expect(lineNumberAt(file, 23)).toBe(5);
  });
});

describe("isInsideCodeFenceAt", () => {
  const file = makeFile("text\n```\ncode here\n```\nafter");

  it("is false before the fence", () => {
    expect(isInsideCodeFenceAt(file, 0)).toBe(false);
  });

  it("is true inside the fence", () => {
    expect(isInsideCodeFenceAt(file, 9)).toBe(true);
  });

  it("is false after the fence closes", () => {
    expect(isInsideCodeFenceAt(file, 23)).toBe(false);
  });

  it("detects tilde fences", () => {
    const tilde = makeFile("x\n~~~\ncode\n~~~\ny");
    expect(isInsideCodeFenceAt(tilde, 7)).toBe(true);
    expect(isInsideCodeFenceAt(tilde, 0)).toBe(false);
  });

  it("handles multiple blocks", () => {
    const multi = makeFile("```\na\n```\nb\n```\nc\n```");
    // Inside the second block ("c").
    const insideSecond = multi.content.indexOf("\nc\n") + 1;
    expect(isInsideCodeFenceAt(multi, insideSecond)).toBe(true);
    // "b" is between the two blocks.
    const between = multi.content.indexOf("\nb\n") + 1;
    expect(isInsideCodeFenceAt(multi, between)).toBe(false);
  });
});

describe("getFileContext cache", () => {
  it("returns the same context for the same file object", () => {
    const file = makeFile("a\nb\nc");
    expect(getFileContext(file)).toBe(getFileContext(file));
  });

  it("returns distinct contexts for distinct files", () => {
    expect(getFileContext(makeFile("a"))).not.toBe(getFileContext(makeFile("a")));
  });
});

describe("large file performance", () => {
  it("answers many lookups quickly", () => {
    const line = "some content line with text\n";
    const content = line.repeat(50000);
    const file = makeFile(content);

    const start = Date.now();
    for (let i = 0; i < 20000; i += 1) {
      lineNumberAt(file, i * 10);
      isInsideCodeFenceAt(file, i * 10);
    }
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
