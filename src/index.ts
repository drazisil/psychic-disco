import EventEmitter from "node:events";
import { readFile, open } from "node:fs/promises";

enum SizeConstants {
  BYTE = 1,
  WORD = 2,
  DWORD = 4,
  QWORD = 8,
  STRING = 0,
  E_RES = 2 * 4,
  E_RES2 = 2 * 10,
}

export interface BinaryFieldBase {
  sizeType: SizeConstants;
  name: string;
  description?: string;
  fileOffset: number;
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

export interface BinaryFieldEntryBuffer extends BinaryFieldBase {
  value: Buffer;
}

export type BinaryFieldEntry =
  | BinaryFieldEntryBytes
  | BinaryFieldEntryNumber
  | BinaryFieldEntryString
  | BinaryFieldEntryBuffer;

const ImageDosSignature = 0x5a4d; // MZ
const ImageNtSignature = 0x00004550; // PE00

const ImageDosHeader: BinaryFieldEntry[] = [
  {
    sizeType: SizeConstants.STRING,
    name: "e_magic",
    value: "",
    lengthOfString: 2,
    description: "Magic number",
    fileOffset: 0x0000,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cblp",
    value: 0x0090,
    description: "Bytes on last page of file",
    fileOffset: 0x0002,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cp",
    value: 0x0003,
    description: "Pages in file",
    fileOffset: 0x0004,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_crlc",
    value: 0x0000,
    description: "Relocations",
    fileOffset: 0x0006,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cparhdr",
    value: 0x0004,
    description: "Size of header in paragraphs",
    fileOffset: 0x0008,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_minalloc",
    value: 0x0000,
    description: "Minimum extra paragraphs needed",
    fileOffset: 0x000a,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_maxalloc",
    value: 0xffff,
    description: "Maximum extra paragraphs needed",
    fileOffset: 0x000c,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_ss",
    value: 0x0000,
    description: "Initial (relative) SS value",
    fileOffset: 0x000e,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_sp",
    value: 0x00b8,
    description: "Initial SP value",
    fileOffset: 0x0010,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_csum",
    value: 0x0000,
    description: "Checksum",
    fileOffset: 0x0012,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_ip",
    value: 0x0000,
    description: "Initial IP value",
    fileOffset: 0x0014,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_cs",
    value: 0x0000,
    description: "Initial (relative) CS value",
    fileOffset: 0x0016,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_lfarlc",
    value: 0x0040,
    description: "File address of relocation table",
    fileOffset: 0x0018,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_ovno",
    value: 0x0000,
    description: "Overlay number",
    fileOffset: 0x001a,
  },
  {
    sizeType: SizeConstants.E_RES,
    name: "e_res",
    value: 0x0000,
    description: "Reserved words",
    fileOffset: 0x001c,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_oemid",
    value: 0x0000,
    description: "OEM identifier (for e_oeminfo)",
    fileOffset: 0x0024,
  },
  {
    sizeType: SizeConstants.WORD,
    name: "e_oeminfo",
    value: 0x0000,
    description: "OEM information; e_oemid specific",
    fileOffset: 0x0026,
  },
  {
    sizeType: SizeConstants.E_RES2,
    name: "e_res2",
    value: 0x0000,
    description: "Reserved words",
    fileOffset: 0x0028,
  },
  {
    sizeType: SizeConstants.DWORD,
    name: "e_lfanew",
    value: 0x00000080,
    description: "File address of new exe header",
    fileOffset: 0x003c,
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
        handle.close();
        this.emit("fileLoaded");
      });
    });
  }

  async parseDosHeader(): Promise<BinaryFieldEntry[]> {
    const dosHeader = ImageDosHeader;
    let offset = 0;

    for (const field of dosHeader) {
      const { sizeType, name, description } = field;
      let size = 0;

      switch (sizeType) {
        case SizeConstants.BYTE:
          size = SizeConstants.BYTE;
          field.value = this.internalBuffer.readUInt8(offset);
          offset += SizeConstants.BYTE;
          break;
        case SizeConstants.WORD:
          size = SizeConstants.WORD;
          field.value = this.internalBuffer.readUInt16LE(offset);
          offset += SizeConstants.WORD;
          break;
        case SizeConstants.DWORD:
          size = SizeConstants.DWORD;
          field.value = this.internalBuffer.readUInt32LE(offset);
          offset += SizeConstants.DWORD;
          break;
        case SizeConstants.QWORD:
          if (name === "e_res") {
            size = SizeConstants.E_RES;
            field.value = this.internalBuffer.subarray(
              offset,
              offset + SizeConstants.E_RES
            );
            offset += SizeConstants.E_RES;
            break;
          } else {
            size = SizeConstants.QWORD;
            field.value = this.internalBuffer.readBigUInt64LE(offset);
            offset += SizeConstants.QWORD;
            break;
          }

        case SizeConstants.STRING:
          const lengthOfString = (field as BinaryFieldEntryString)
            .lengthOfString;
          size = lengthOfString;
          field.value = this.internalBuffer
            .subarray(offset, offset + lengthOfString)
            .toString();
          offset += lengthOfString;
          break;

        case SizeConstants.E_RES2:
          size = SizeConstants.E_RES2;
          field.value = this.internalBuffer.subarray(
            offset,
            offset + SizeConstants.E_RES2
          );
          offset += SizeConstants.E_RES2;
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
