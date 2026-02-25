// WASM glue XSS - JS side
const go = new Function('alert(1)')();
