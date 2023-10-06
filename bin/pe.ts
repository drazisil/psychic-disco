#!/usr/bin/env node

import parse from "../src/index.js";

const pe = parse(process.argv[2]);

pe.on("dosHeaderParsed", () => {
  console.dir(pe.dosHeader);
});

pe.parse();
