import { Command } from "@tauri-apps/plugin-shell";

export type ScannerFinding = {
  check: string;
  severity: string;
  status: string;
  value?: string;
};

export type HeaderScanResult = {
  url: string;
  status_code: number;
  findings: ScannerFinding[];
};

type ScannerMessage = {
  id?: string;
  event?: "started" | "result" | "error";
  data?: HeaderScanResult;
  error?: string;
};

const SIDE_CAR = "binaries/dadadevourer-scanner";

function parseMessage(line: string): ScannerMessage {
  let message: unknown;
  try {
    message = JSON.parse(line);
  } catch {
    throw new Error("Scanner returned invalid JSON");
  }
  if (!message || typeof message !== "object") {
    throw new Error("Scanner returned an invalid message");
  }
  return message as ScannerMessage;
}

export async function runHeadersScan(target: string): Promise<HeaderScanResult> {
  const id = crypto.randomUUID();
  const command = Command.sidecar(SIDE_CAR);
  let settled = false;
  let stdoutBuffer = "";

  return new Promise<HeaderScanResult>(async (resolve, reject) => {
    const finishError = (error: Error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const finishSuccess = (result: HeaderScanResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    command.stdout.on("data", (chunk) => {
      stdoutBuffer += String(chunk);
      const lines = stdoutBuffer.split(/\r?\n/);
      stdoutBuffer = lines.pop() ?? "";
      for (const line of lines.map((item) => item.trim()).filter(Boolean)) {
        try {
          const message = parseMessage(line);
          if (message.id !== id) continue;
          if (message.event === "error") {
            finishError(new Error(message.error || "Scanner failed"));
          } else if (message.event === "result" && message.data) {
            finishSuccess(message.data);
          }
        } catch (error) {
          finishError(error instanceof Error ? error : new Error(String(error)));
        }
      }
    });

    command.stderr.on("data", (chunk) => {
      console.warn("DadaDevourer scanner:", String(chunk));
    });

    command.on("error", (error) => finishError(new Error(String(error))));
    command.on("close", ({ code, signal }) => {
      if (!settled) {
        finishError(new Error(`Scanner exited before returning a result (code=${code ?? "unknown"}, signal=${signal ?? "none"})`));
      }
    });

    try {
      const child = await command.spawn();
      await child.write(`${JSON.stringify({ id, command: "headers_scan", target })}\n`);
    } catch (error) {
      finishError(error instanceof Error ? error : new Error(String(error)));
    }
  });
}
