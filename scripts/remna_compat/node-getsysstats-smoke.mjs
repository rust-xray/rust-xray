#!/usr/bin/env node
/**
 * Optional plaintext gRPC smoke for Xray StatsService.GetSysStats (h2c / insecure).
 *
 * Usage:
 *   node scripts/remna_compat/node-getsysstats-smoke.mjs [host:port]
 *
 * Requires @grpc/grpc-js and @grpc/proto-loader, or run check-api.sh with grpcurl instead.
 */

const addr = process.argv[2] ?? "127.0.0.1:61000";
const [host, port] = addr.includes(":") ? addr.split(":") : ["127.0.0.1", addr];

async function main() {
  let grpc;
  let protoLoader;
  try {
    grpc = await import("@grpc/grpc-js");
    protoLoader = await import("@grpc/proto-loader");
  } catch {
    console.error("SKIP: install @grpc/grpc-js and @grpc/proto-loader, or use:");
    console.error("  bash scripts/remna_compat/check-api.sh", addr);
    process.exit(2);
  }

  const path = new URL("../../proto/app/stats/command/command.proto", import.meta.url);
  const packageDefinition = protoLoader.loadSync(path, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [new URL("../../proto", import.meta.url).pathname],
  });
  const proto = grpc.loadPackageDefinition(packageDefinition);
  const client = new proto.xray.app.stats.command.StatsService(
    `${host}:${port}`,
    grpc.credentials.createInsecure(),
  );

  await new Promise((resolve, reject) => {
    client.GetSysStats({}, (err, resp) => {
      if (err) {
        reject(err);
        return;
      }
      console.log("PASS GetSysStats", JSON.stringify(resp));
      resolve();
    });
  });
}

main().catch((err) => {
  console.error("FAIL GetSysStats", err.message ?? err);
  process.exit(1);
});
