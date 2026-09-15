// Read-only diagnostic: show topology and counts, never credentials or records.
const mongoose = require("mongoose");
const { env } = require("../dist/config/env.js");

async function main() {
  await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  const hello = await mongoose.connection.db.admin().command({ hello: 1 });
  console.log("Transactions supported:", Boolean(hello.setName || hello.msg === "isdbgrid"));
  for (const name of ["authusers", "credentials", "otpchallenges", "securityevents"]) {
    const count = await mongoose.connection.db.collection(name).countDocuments();
    console.log(name + ": " + count);
  }
}
main().catch(() => {
  console.error("Database diagnostic failed.");
  process.exitCode = 1;
}).finally(() => mongoose.disconnect());
