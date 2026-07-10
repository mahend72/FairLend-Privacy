#!/usr/bin/env node
// R_acc witness/public-input builder (Phase 3B).
//
// This script is the ONLY place the "Bank" EdDSA-Poseidon signing
// operation and the Poseidon commitment are computed for the R_acc
// demonstration -- see r_acc.circom's header comment for why
// EdDSA-Poseidon/Poseidon-commitment are used here INSTEAD OF the
// Ed25519 signature / unspecified generic commitment the rest of this
// codebase's Bank role (fairlend.roles.bank) actually uses.
//
// Subcommands:
//   keygen
//     -> prints {"privateKeyHex": ..., "Ax": ..., "Ay": ...} (a fresh
//        random Bank EdDSA-Poseidon keypair; Ax/Ay are the PUBLIC key,
//        as decimal-string BN254 scalar-field elements).
//
//   build <privateKeyHex> <uid> <acc> <r_acc>
//     -> prints the complete r_acc.circom witness input JSON:
//        {Ax, Ay, uid, Cacc, acc, r_acc, S, R8x, R8y}
//        uid/acc/r_acc are taken as decimal-string field elements.
import { buildEddsa, buildPoseidon } from "circomlibjs";
import crypto from "crypto";

function toDecStr(x) {
  return x.toString();
}

async function main() {
  const [, , cmd, ...args] = process.argv;
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  if (cmd === "keygen") {
    const prv = crypto.randomBytes(32);
    const A = eddsa.prv2pub(prv);
    console.log(JSON.stringify({
      privateKeyHex: prv.toString("hex"),
      Ax: toDecStr(F.toObject(A[0])),
      Ay: toDecStr(F.toObject(A[1])),
    }));
    return;
  }

  if (cmd === "build") {
    const [privateKeyHex, uidStr, accStr, rAccStr] = args;
    const prv = Buffer.from(privateKeyHex, "hex");
    const A = eddsa.prv2pub(prv);

    const uid = BigInt(uidStr);
    const acc = BigInt(accStr);
    const rAcc = BigInt(rAccStr);

    // NOTE: signPoseidon/poseidon expect field elements in their RAW
    // internal (F-module) representation, not a plain BigInt -- only
    // convert via F.toObject() for the final JSON output below. Passing
    // a BigInt where a raw F-element is expected fails inside
    // signPoseidon (F.toRprLE/msg.length) with a confusing
    // "offset is out of bounds" error; this was found by testing, not
    // assumed from documentation.
    const M = poseidon([uid, acc]);
    const sig = eddsa.signPoseidon(prv, M);

    const Cacc = F.toObject(poseidon([uid, acc, rAcc]));

    console.log(JSON.stringify({
      Ax: toDecStr(F.toObject(A[0])),
      Ay: toDecStr(F.toObject(A[1])),
      uid: toDecStr(uid),
      Cacc: toDecStr(Cacc),
      acc: toDecStr(acc),
      r_acc: toDecStr(rAcc),
      S: toDecStr(sig.S),
      R8x: toDecStr(F.toObject(sig.R8[0])),
      R8y: toDecStr(F.toObject(sig.R8[1])),
    }));
    return;
  }

  console.error(`Unknown or missing subcommand: ${cmd}. Use 'keygen' or 'build <privHex> <uid> <acc> <r_acc>'.`);
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
