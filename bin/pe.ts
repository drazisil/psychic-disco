#!/usr/bin/env node

import parse from "../src/index.js";

const pe = parse(process.argv[2]);

console.log(pe.toString());
