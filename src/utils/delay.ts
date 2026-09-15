export async function delay(milliseconds: number): Promise<void> {
  // Yield the event loop; this does not busy-wait or occupy an Argon2 worker.
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}
