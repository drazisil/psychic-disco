class PE {
  input: string;

  constructor(input: string) {
    this.input = input;
  }

  toString(): string {
    return this.input;
  }
}

export default function(input: string): PE {
  return new PE(input);
}
