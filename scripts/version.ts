const decoder = new TextDecoder('utf-8');
const encoder = new TextEncoder();

async function updateVersion() {
  const packageJsonText = decoder.decode(await Deno.readFile('./package.json'));
  const packageJson = JSON.parse(packageJsonText);
  const version = packageJson.version;

  const versionTsContent = `export const version = '${version}';\n`;
  await Deno.writeFile('src/version.ts', encoder.encode(versionTsContent));
}

updateVersion().catch(error => {
  console.error('failed to update version.ts:', error);
  Deno.exit(1);
});
