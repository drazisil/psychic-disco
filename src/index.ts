import EventEmitter from "node:events";
import { readFile, open } from "node:fs/promises";
import { as } from "vitest/dist/reporters-5f784f42.js";

enum SizeConstants {
  BYTE = 1,
  WORD = 2,
  DWORD = 4,
  QWORD = 8,
  STRING = 0,
}

export interface BinaryFieldBase {
  sizeType: SizeConstants;
  name: string;
  description?: string;
}

export interface BinaryFieldEntryBytes extends BinaryFieldBase {
  value: Buffer;
}

export interface BinaryFieldEntryNumber extends BinaryFieldBase {
  value: number | bigint;
}

export interface BinaryFieldEntryString extends BinaryFieldBase {
  value: string;
  lengthOfString: number;
}

export type BinaryFieldEntry =
  | BinaryFieldEntryBytes
  | BinaryFieldEntryNumber
  | BinaryFieldEntryString;

const ImageDosSignature = 0x5a4d; // MZ
const ImageNtSignature = 0x00004550; // PE00

const ImageDosHeader: BinaryFieldEntry[] = [
  {
    sizeType: SizeConstants.WORD,
    name: "e_magic",
    value: ImageDosSignature,
    description: "Magic number",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cblp",
    value: 0x0090,
    description: "Bytes on last page of file",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cp",
    value: 0x0003,
    description: "Pages in file",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_crlc",
    value: 0x0000,
    description: "Relocations",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cparhdr",
    value: 0x0004,
    description: "Size of header in paragraphs",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_minalloc",
    value: 0x0000,
    description: "Minimum extra paragraphs needed",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_maxalloc",
    value: 0xffff,
    description: "Maximum extra paragraphs needed",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_ss",
    value: 0x0000,
    description: "Initial (relative) SS value",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_sp",
    value: 0x00b8,
    description: "Initial SP value",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_csum",
    value: 0x0000,
    description: "Checksum",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_ip",
    value: 0x0000,
    description: "Initial IP value",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cs",
    value: 0x0000,
    description: "Initial (relative) CS value",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_lfarlc",
    value: 0x0040,
    description: "File address of relocation table",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_ovno",
    value: 0x0000,
    description: "Overlay number",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_res",
    value: 0x0000,
    description: "Reserved words",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_oemid",
    value: 0x0000,
    description: "OEM identifier (for e_oeminfo)",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_oeminfo",
    value: 0x0000,
    description: "OEM information; e_oemid specific",
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_res2",
    value: 0x0000,
    description: "Reserved words",
  },
  {
    sizeType: SizeConstants.DWORD,
    name: "e_lfanew",
    value: 0x00000080,
    description: "File address of new exe header",
  },
];

const CoffHeader: BinaryFieldEntry[] = [];

export interface PeProgram {}

/**
 * PE class
 * 
 * @event fileLoaded
 * @event dosHeaderParsed
 */
class PE extends EventEmitter {
  input: string;
  internalBuffer: Buffer;
  dosHeader: BinaryFieldEntry[] = [];
  fileLoaded: boolean = false;

  constructor(input: string) {
    super();
    this.input = input;
    this.internalBuffer = Buffer.alloc(0);

    open(this.input, "r").then((handle) => {
      readFile(handle).then((buffer) => {
        this.internalBuffer = buffer;
        this.fileLoaded = true;
        this.emit("fileLoaded");
      });
    });
  }

  async parseDosHeader(): Promise<BinaryFieldEntry[]> {
    const dosHeader = ImageDosHeader;
    let offset = 0;

    for (const field of dosHeader) {
      const { sizeType, name, description } = field;

      switch (sizeType) {
        case SizeConstants.BYTE:
          field.value = this.internalBuffer.readUInt8(offset);
          offset += SizeConstants.BYTE;
          break;
        case SizeConstants.WORD:
          field.value = this.internalBuffer.readUInt16LE(offset);
          offset += SizeConstants.WORD;
          break;
        case SizeConstants.DWORD:
          field.value = this.internalBuffer.readUInt32LE(offset);
          offset += SizeConstants.DWORD;
          break;
        case SizeConstants.QWORD:
          field.value = this.internalBuffer.readBigUInt64LE(offset);
          offset += SizeConstants.QWORD;
          break;
        case SizeConstants.STRING:
          const lengthOfString = (field as BinaryFieldEntryString)
            .lengthOfString;
          field.value = this.internalBuffer
            .subarray(offset, offset + lengthOfString)
            .toString();
          offset += lengthOfString;
          break;
      }
    }

    return dosHeader;
  }

  async parse(): Promise<void> {
    if (!this.fileLoaded) {
      await new Promise((resolve) => {
        this.once("fileLoaded", resolve);
      });
    }

    this.parseDosHeader().then((dosHeader) => {
      this.dosHeader = dosHeader;
      this.emit("dosHeaderParsed");
    });
  }

  toString(): string {
    return this.input;
  }
}

export default function (input: string): PE {
  return new PE(input);
}
