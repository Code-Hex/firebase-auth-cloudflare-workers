export interface Bindings {
  TEST_NAMESPACE: KVNamespace;
}

declare global {
  function getMiniflareBindings(): Bindings;
}
