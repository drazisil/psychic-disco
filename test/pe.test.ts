import pe from "../src/index.js";
import { describe, it } from "vitest";

describe("pe", () => {

    it("should parse a PE file", () => {
        const peFile = pe("test/pe.exe");
        console.log(peFile.toString());
    });
});
