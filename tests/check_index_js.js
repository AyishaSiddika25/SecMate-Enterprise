const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync("index.html", "utf8");
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)];

if (!scripts.length) {
    throw new Error("No inline scripts were found in index.html");
}

for (const [index, match] of scripts.entries()) {
    new vm.Script(match[1], { filename: `index-inline-${index + 1}.js` });
}

console.log(`Validated ${scripts.length} inline script block(s).`);
